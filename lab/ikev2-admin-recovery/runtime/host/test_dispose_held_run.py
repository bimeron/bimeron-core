"""Hermetic tests for dispose-held-run.py; every external effect is a fake."""
import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import struct
import sys
import unittest
import uuid

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('dispose_held_run', HERE / 'dispose-held-run.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
NONCE = '4fb188290013c182d2cb845f4fe2d34a68bf053a5d79a4d925eca9e1c2852c61'
# 4fb18829-shaped retained processes: (pid, name, parent, marker, journal), role order.
PROCESSES = (
    (55576, 'python.exe', 62144, 'pinned_watcher.py', 'journalContainment'),
    (63848, 'powershell.exe', 62144, 'resident-main.ps1', None),
    (64808, 'powershell.exe', 62144, 'prepare-task.ps1', None),
    (62144, 'python.exe', 42552, 'preparation.py', 'journalOwner'),
)
# Short root: the fixture mirrors 64-hex run paths (MAX_PATH).
TEMP = pathlib.Path(__import__('tempfile').gettempdir())
REAL_EVIDENCE = pathlib.Path(r'<LAB_PRIVATE_ROOT>\evidence-4fb18829')
REAL_EVIDENCE_9DE = pathlib.Path(r'<LAB_PRIVATE_ROOT>\evidence-9de2f235')
REAL_EVIDENCE_F89 = pathlib.Path(r'<LAB_PRIVATE_ROOT>\evidence-f8956ea0')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return json.dumps(value, separators=(',', ':')).encode()


def b64(raw):
    return {'$bytes': base64.b64encode(raw).decode()}


CAPTURE = '/home/lab/step9-' + 'c' * 64 + '/capture-supervisor.py'
IDENTITY = dict(pid=7, start='1', boot='boot', command='d' * 64)
PCAP = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
NFT = {'nftables': [{'metainfo': {'version': '1'}}, {'table': {'family': 'inet', 'name': 'lab', 'handle': 1}}]}
TOPOLOGY = {'links': [{'ifname': 'labnet'}], 'addresses': [{'ifname': 'labnet', 'addr_info': [
    {'local': '192.0.2.1', 'valid_life_time': 5, 'preferred_life_time': 5}]}], 'routes': [{'dst': 'default'}]}
SERVICES = {'BFE': 'Running', 'RasMan': 'Running', 'IKEEXT': 'Stopped', 'PolicyAgent': 'Stopped'}
TIMES = {55576: ('2026-11-05T21:41:55.2952720Z', '134383885152952726'),
         63848: ('2026-11-05T21:41:56.2144200Z', None),
         64808: ('2026-11-05T21:42:03.1100540Z', None),
         62144: ('2026-11-05T21:41:51.9946690Z', '134383885119946691')}
PYTHON = r'C:\lab\admission\python\python.exe'
PS = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
ADMISSION = r'C:\lab\admission'
SAFE_SDDL = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)'


def build_evidence(root):
    files = {}
    p = 'host/private-root/'
    config = enc(dict(schema='full300-owner-config-v1', nonce=NONCE, taskName='BimeronFull300Owner-' + NONCE))
    seal = enc(dict(schema='full300-owner-command-v1', nonce=NONCE, configSHA256=sha(config), seq=1,
                    op='seal-no-launch', body={}))
    files[p + 'owner-transport/config.json'] = config
    files[p + 'owner-transport/commands/00000001.json'] = seal
    files[p + 'owner-transport/task-registration.json'] = b'{"xml":"<Task/>"}'
    files[p + 'owner-transport/task-instance.json'] = b'{"instanceGuid":"{4D8B7BAF-A48B-43EA-80AF-9505B1502AC0}"}'
    ssh = [tool.SSH, '-F', 'none', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', 'lab@192.0.2.9']
    files[p + 'host-supervisor-config.json'] = enc(dict(nonce=NONCE, capture=IDENTITY,
        query=ssh + ['sudo python3 ' + CAPTURE + ' status ' + NONCE]))
    for seq, op in ((1, 'principal'), (2, 'seal-no-launch')):
        target = 'owner-transport\\commands\\00000001.json' if op == 'seal-no-launch' else 'context.json'
        files[p + 'guest-control/resident-request-%020d.json' % seq] = enc(dict(
            sequence=seq, mode='submit', operation=op, path='C:\\held\\' + target,
            requestSHA256=sha(seal) if op == 'seal-no-launch' else 'e' * 64))
        files[p + 'guest-control/resident-response-%020d.json' % seq] = enc(dict(
            sequence=seq, state='Failed' if op == 'seal-no-launch' else 'Collected',
            output=None if op == 'seal-no-launch' else 'eA=='))
        files[p + 'guest-control/resident-reserved-%020d.json' % seq] = enc(dict(sequence=seq))
    files[p + 'guest-control/resident.stdout'] = b'log\n'
    private = root / 'held' / ('capture-prep-' + NONCE)
    cmd = {55576: 'python.exe pinned_watcher.py --config ' + str(private) + '\\host-supervisor-config.json',
           63848: 'powershell.exe resident-main.ps1 ' + NONCE,
           64808: 'powershell.exe prepare-task.ps1 ' + NONCE, 62144: 'python.exe preparation.py'}
    processes = []
    for pid, name, parent, _, _ in PROCESSES:
        processes.append(dict(pid=pid, parent=parent, name=name, created=TIMES[pid][0],
                              exe=PYTHON if name == 'python.exe' else PS, cmd=cmd[pid]))
    files['host/process-tree.json'] = enc(dict(schema='host-process-tree-v1', processes=processes,
        journalOwner=dict(pid=62144, creationFileTime=TIMES[62144][1]),
        journalContainment=dict(pid=55576, creationFileTime=TIMES[55576][1])))
    baseline = enc(dict(nft=NFT, topology=TOPOLOGY, labnetFeatures=b64(b'rx: on\n'), uplinkFeatures=b64(b'tx: on\n'),
                        services=SERVICES, guest={}, absence={}, git={}))
    files['host/admission/baseline.json'] = baseline
    files['host/admission/config.json'] = enc(dict(baseline=dict(sha256=sha(baseline)), admissionRoot=ADMISSION))
    files['guest/guest-state.json'] = enc(dict(taskState='Running', remoteListing=[
        dict(path='C:\\BimeronFull300\\' + NONCE + '\\transport\\config.json')],
        processes=[dict(pid=5368, name='powershell.exe', cmd='powershell -File C:/BimeronFull300/' + NONCE + '/owner-supervisor.ps1')]))
    files['guest/BimeronFull300/' + NONCE + '/transport/config.json'] = config
    entries = []
    for relative, raw in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        entries.append(dict(path=relative, size=len(raw), sha256=sha(raw)))
    (root / 'MANIFEST.json').write_bytes(enc(dict(schema='evidence-manifest-v1', run=NONCE, files=entries)))
    for name in list(tool.PRIVATE_FILES) + [k[len(p):] for k in files if k.startswith(p + 'guest-control/')]:
        target = private / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(files[p + name])
    return private


def guest_state(**changes):
    value = dict(schema='held-run-guest-state-v1', nonce=NONCE, computer='<LAB_GUEST_NAME>', rootExists=True,
                 probeExists=True, commands=[], responses=[], noLaunch=False,
                 tasks=[dict(state=4, instances=['{4D8B7BAF-A48B-43EA-80AF-9505B1502AC0}'])],
                 processes=[dict(pid=5368, name='powershell.exe', commandLine='-File C:/BimeronFull300/' + NONCE + '/owner-supervisor.ps1')],
                 udp=[], services=dict(SERVICES), policy={s: 'Undefined' for s in tool.PERSISTENT_POLICY},
                 ras='No connections\r\nCommand completed successfully.\r\n')
    value.update(changes)
    return value


DONE = dict(rootExists=True, probeExists=True, tasks=[], processes=[], noLaunch=True,
            commands=['00000001.json', '00000002.json'], responses=['00000001.json', '00000002.json'])


class Fake:
    def __init__(self, private):
        self.private = private
        self.calls = []
        self.states = [guest_state(), guest_state(**DONE), guest_state(**dict(DONE, rootExists=False, probeExists=False))]
        self.network = dict(schema='host-network-readonly-v1', sid='S-1', adapters=[{'Name': 'wg'}],
                            adapterLinkSpeeds=[{'InterfaceGuid': '{1}', 'LinkSpeed': '1 Gbps'}], routes=[],
                            dns=[], vpnUser=[], vpnAllUsers=[])
        self.deviate_after = None
        self.outcome = 'accepted'
        self.identities = {pid: dict(pid=pid, creationFileTime=int(TIMES[pid][1]) if TIMES[pid][1] else
                                     tool.filetime(TIMES[pid][0]) + 3,
                                     image=PYTHON if pid in (55576, 62144) else PS, parent=parent)
                           for pid, _, parent, _, _ in PROCESSES}
        self.stopped = False
        self.null_polls = 0
        self.exit_code = 0
        self.sleeps = []
        self.dns_after = None
        self.scan_rows = []
        self.killed = []
        self.sink_listed = True
        self.gone = set()
        self.gone_on_terminate = set()
        self.extra_rows = []
        self.once_sha = 'f' * 64

    def sleep(self, seconds):
        self.sleeps.append(seconds)

    def guest_control(self):
        self.calls.append(('guest-control',))
        root = self.private / 'guest-control'
        return {f.name: sha(f.read_bytes()) for f in root.iterdir()}

    def process_scan(self):
        self.calls.append(('scan',))
        rows = [dict(pid=os.getpid(), parent=4242, name='python.exe', image=PYTHON, creationFileTime=1,
                     commandLine='python -I dispose-held-run.py run --approve-nonce ' + NONCE),
                dict(pid=4242, parent=1, name='py.exe', image='C:\\py.exe', creationFileTime=1,
                     commandLine='py dispose-held-run.py --approve-nonce ' + NONCE),
                dict(pid=777, parent=os.getpid(), name='powershell.exe', image=PS, creationFileTime=1,
                     commandLine='powershell -File dispose-held-run.ps1 -RunNonce ' + NONCE)]
        rows += [r for r in self.scan_rows if r['pid'] not in self.killed]
        rows += self.extra_rows
        return dict(schema='host-processes-readonly-v1', self=777, processes=rows)

    def private_files(self, names):
        self.calls.append(('private',))
        return {n: (self.private / n).read_bytes() for n in names}

    def host_network(self):
        self.calls.append(('network',))
        count = sum(1 for c in self.calls if c[0] == 'network')
        if self.deviate_after is not None and count > self.deviate_after:
            return dict(self.network, routes=[{'changed': True}])
        if self.dns_after is not None and count % 2 == 0:
            return dict(self.network, dns=self.dns_after)
        return self.network

    def guest_state(self):
        self.calls.append(('guest-state',))
        return self.states.pop(0)

    def guest_remove(self, nonce):
        self.calls.append(('remove', nonce))
        return dict(targets=['C:/BimeronFull300/' + nonce, 'C:/BimeronStep10Probe/' + nonce], absent=[True, True])

    def deliver(self, path):
        self.calls.append(('deliver', path.name))
        ot = path.parent.parent
        raw = path.read_bytes()
        command = json.loads(raw)
        config = (ot / 'config.json').read_bytes()
        refs = []
        if command['op'] == 'seal-no-launch':
            proof = enc(dict(schema='full300-no-launch-v1', nonce=NONCE, configSHA256=sha(config),
                             supervisorOnceSHA256=self.once_sha, sealCommandSHA256=sha(raw), launchAttempted=False, sealed=True))
            (ot / 'proofs/no-launch.json').write_bytes(proof)
            refs.append(dict(name='no-launch.json', sha256=sha(proof), length=len(proof)))
            state = 'SEALED_NO_LAUNCH'
        else:
            proof = enc(dict(schema='full300-supervisor-exit-v1', nonce=NONCE, configSHA256=sha(config),
                             supervisorOnceSHA256=self.once_sha, exitCommandSHA256=sha(raw),
                             proofSHA256=command['body']['noLaunch']['sha256'], reason='sealed-no-launch'))
            (ot / 'proofs/supervisor-exit-ready.json').write_bytes(proof)
            refs.append(dict(name='supervisor-exit-ready.json', sha256=sha(proof), length=len(proof)))
            (ot / 'task-final.json').write_bytes(enc(dict(state=3, instanceGuids=[], lastTaskResult=0,
                                                          instanceGuid='{4D8B7BAF-A48B-43EA-80AF-9505B1502AC0}')))
            state = 'EXIT_READY'
        response = enc(dict(schema='full300-owner-response-v1', nonce=NONCE, configSHA256=sha(config),
                            seq=command['seq'], commandSHA256=sha(raw), outcome=self.outcome, state=state,
                            owner=None, refs=refs, error=None))
        (ot / 'responses' / path.name).write_bytes(response)
        return 0, response, b''

    def ssh(self, argv, data):
        command = argv[-1]
        self.calls.append(('ssh', command))
        assert argv[:3] == [tool.SSH, '-F', 'none']
        remote = '/var/lib/step8/run-' + NONCE + '/'
        if command == 'sudo python3 -':
            return b''
        if command.endswith('cleanup-confirmed.json'):
            return enc(dict(Nonce=NONCE, OwnedRASAbsent=True, WFPOwnerCleaned=True))
        if command.endswith('health.json'):
            if not self.stopped:
                return enc(dict(Nonce=NONCE, ExitCode=None))
            if self.null_polls > 0:
                self.null_polls -= 1
                return enc(dict(Nonce=NONCE, ExitCode=None))
            return enc(dict(Nonce=NONCE, ExitCode=self.exit_code))
        if ' stop ' + NONCE in command:
            self.stopped = True
            return b''
        if command.endswith('ingress.pcap'):
            return PCAP
        if command.endswith('capture.log'):
            return b'0 packets dropped by kernel\n'
        if command.endswith('identity.json'):
            return enc(IDENTITY)
        if command.startswith('sudo systemctl list-units'):
            return ('step10-prep-' + NONCE + '.service loaded active running x\n').encode() if self.sink_listed else b''
        if command == 'sudo systemctl stop step10-prep-' + NONCE:
            self.sink_listed = False
            return b''
        if command == remote and False:
            return b''
        if command.endswith('sink-exit.json'):
            import sink_contract
            return enc(dict(schema='fresh-sink-exit-v1', nonce=NONCE, unit='step10-prep-' + NONCE + '.service',
                            contractSHA256=sink_contract.CONTRACT_SHA256, invocationId='a' * 32, result='success',
                            exitCode='exited', exitStatus='0'))
        if command == 'sudo nft -j list ruleset':
            return enc({'nftables': [{'metainfo': {'version': '2'}}, {'table': {'family': 'inet', 'name': 'lab', 'handle': 9}}]})
        if command == 'sudo ethtool -k labnet':
            return b'rx: on\n'
        if command == 'sudo ethtool -k uplink':
            return b'tx: on\n'
        if command == 'ip -j link show':
            return enc(TOPOLOGY['links'])
        if command == 'ip -j address show':
            return enc([{'ifname': 'labnet', 'addr_info': [{'local': '192.0.2.1', 'valid_life_time': 1, 'preferred_life_time': 1}]}])
        if command == 'ip -j route show table all':
            return enc(TOPOLOGY['routes'])
        raise AssertionError('Unexpected ssh command: ' + command)

    def process_identity(self, pid):
        self.calls.append(('identity', pid))
        if pid in self.gone:
            return None
        return dict(self.identities[pid])

    def terminate(self, pid, check, gone_ok=False):
        if pid in self.gone_on_terminate:
            assert gone_ok
            self.calls.append(('gone', pid))
            self.killed.append(pid)
            return dict(pid=pid, terminated=False, gone=True, identity=None)
        check(dict(self.identities[pid]))
        self.calls.append(('terminate', pid))
        self.killed.append(pid)
        return dict(pid=pid, terminated=True, exitCode=1)


class DisposeTests(unittest.TestCase):
    def setUp(self):
        self.root = TEMP / ('dhr-' + uuid.uuid4().hex[:8])
        self.root.mkdir(parents=True)
        self.private = build_evidence(self.root / 'evidence')
        self.plan = tool.validate(tool.Evidence(self.root / 'evidence'))
        self.fake = Fake(self.private)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.disposition = tool.Disposition(self.plan, self.fake, tool.Journal(self.work, NONCE))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def final(self):
        return json.loads((self.work / 'final-record.json').read_bytes())

    def effects(self, kind):
        return [c for c in self.fake.calls if c[0] == kind]

    def test_dry_run_validates_evidence_only(self):
        import contextlib, io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(tool.main(['dry-run', '--evidence', str(self.root / 'evidence')]), 0)
        self.assertEqual(json.loads(out.getvalue())['valid'], True)
        self.assertEqual(self.plan['sealSHA256'], sha((self.private / 'owner-transport/commands/00000001.json').read_bytes()))
        self.assertEqual(self.plan['ssh'][:3], [tool.SSH, '-F', 'none'])

    @unittest.skipUnless((REAL_EVIDENCE / 'MANIFEST.json').exists(), 'evidence copy absent')
    def test_dry_run_against_real_evidence_copy(self):
        plan = tool.validate(tool.Evidence(REAL_EVIDENCE))
        self.assertEqual([p['pid'] for p in plan['processes']], [55576, 63848, 64808, 62144])
        self.assertEqual([p['role'] for p in plan['processes']], ['watcher', 'resident', 'task-helper', 'owner'])
        self.assertEqual(plan['supervisorPid'], 5368)
        self.assertEqual(plan['modes'], dict(B1='act', B2='act', B3='act', B4='act'))

    @unittest.skipUnless((REAL_EVIDENCE_9DE / 'MANIFEST.json').exists(), 'evidence copy absent')
    def test_dry_run_against_real_9de2f235_evidence_copy(self):
        evidence = tool.Evidence(REAL_EVIDENCE_9DE)
        self.assertTrue(evidence.manifestSHA256.startswith('2260b7f3'))
        plan = tool.validate(evidence)
        self.assertEqual(plan['modes'], dict(B1='confirm', B2='act', B3='confirm', B4='act'))
        self.assertEqual([(p['role'], p['pid'], p['creationFileTime']) for p in plan['processes']],
                         [('watcher', 80044, 134383940282437166), ('owner', 80928, 134383940249249215)])
        self.assertEqual(plan['removalTargets'], ['C:/BimeronFull300/' + evidence.nonce,
                                                  'C:/BimeronStep10Probe/' + evidence.nonce])

    def test_full_order_journal_and_final_record(self):
        for step in tool.STEPS:
            self.disposition.run(step)
        kinds = [c[0] for c in self.fake.calls if c[0] != 'network']
        delivered = [c[1] for c in self.effects('deliver')]
        self.assertEqual(delivered, ['00000001.json', '00000002.json'])
        self.assertEqual(kinds.index('remove') > kinds.index('deliver'), True)
        self.assertLess(max(i for i, k in enumerate(kinds) if k == 'deliver'), kinds.index('remove'))
        self.assertLess(kinds.index('remove'), kinds.index('ssh'))
        self.assertLess(max(i for i, k in enumerate(kinds) if k == 'ssh'), kinds.index('identity'))
        self.assertEqual([c[1] for c in self.effects('terminate')], [55576, 63848, 64808, 62144])
        last_identity = max(i for i, c in enumerate(self.fake.calls) if c[0] == 'identity')
        first_terminate = min(i for i, c in enumerate(self.fake.calls) if c[0] == 'terminate')
        self.assertLess(last_identity, first_terminate)
        ssh = [c[1] for c in self.effects('ssh')]
        self.assertEqual(ssh[0], 'sudo python3 -')
        self.assertLess(ssh.index('sudo python3 ' + CAPTURE + ' stop ' + NONCE), ssh.index('sudo systemctl stop step10-prep-' + NONCE))
        self.assertEqual(len(self.effects('network')), 8)
        self.assertEqual((self.work / 'owner-transport/commands/00000001.json').read_bytes(),
                         (self.private / 'owner-transport/commands/00000001.json').read_bytes())
        exit_command = json.loads((self.work / 'owner-transport/commands/00000002.json').read_bytes())
        self.assertEqual((exit_command['seq'], exit_command['op'], list(exit_command['body'])), (2, 'exit-supervisor', ['noLaunch']))
        final = self.final()
        self.assertEqual((final['label'], final['status'], final['settled'], final['normalCleanup']),
                         (tool.LABEL, 'DISPOSED', False, False))
        self.assertEqual(sorted(final['provenSteps']), list(tool.STEPS))
        self.assertTrue(all((self.work / 'journal' / name).is_file() for name in final['journal']))
        self.assertTrue((self.work / 'observer-archive/ingress.pcap').read_bytes() == PCAP)
        with self.assertRaises(tool.Refusal):
            self.disposition.run('B4')

    def test_steps_out_of_order_refused_without_effects(self):
        for step in ('B2', 'B3', 'B4'):
            with self.assertRaisesRegex(tool.Refusal, 'B1 not proven'):
                self.disposition.run(step)
        self.assertEqual(self.fake.calls, [])
        self.disposition.run('B1')
        with self.assertRaisesRegex(tool.Refusal, 'B2 not proven'):
            self.disposition.run('B3')

    def test_nonempty_guest_commands_refuses_delivery_and_retry(self):
        self.fake.states[0] = guest_state(commands=['00000001.json'])
        with self.assertRaisesRegex(tool.Refusal, 'commands/responses not empty'):
            self.disposition.run('B1')
        self.assertEqual(self.effects('deliver'), [])
        self.assertEqual(self.effects('private'), [])
        final = self.final()
        self.assertEqual((final['status'], final['stoppedAt'], final['settled'], final['normalCleanup'], final['label']),
                         ('STOPPED', 'B1', False, False, tool.LABEL))
        with self.assertRaisesRegex(tool.Refusal, 'finalized'):
            self.disposition.run('B1')

    def test_supervisor_identity_must_match_evidence(self):
        self.fake.states[0] = guest_state(processes=[dict(pid=9999, commandLine='owner-supervisor.ps1 ' + NONCE)])
        with self.assertRaisesRegex(tool.Refusal, 'original supervisor'):
            self.disposition.run('B1')
        self.assertEqual(self.effects('deliver'), [])

    def test_held_root_must_equal_evidence(self):
        (self.private / 'owner-transport/commands/00000001.json').write_bytes(b'{"changed":true}')
        with self.assertRaisesRegex(tool.Refusal, 'differs from evidence'):
            self.disposition.run('B1')
        self.assertEqual(self.effects('deliver'), [])

    def test_rejected_seal_stops_before_exit_supervisor(self):
        self.fake.outcome = 'rejected'
        with self.assertRaisesRegex(tool.Refusal, 'not accepted'):
            self.disposition.run('B1')
        self.assertEqual([c[1] for c in self.effects('deliver')], ['00000001.json'])

    def test_wrong_nonce_is_refused(self):
        with self.assertRaisesRegex(tool.Refusal, 'Removal nonce'):
            tool.LiveEffects(self.plan, self.private, tool.DRIVER).guest_remove('b' * 64)
        import contextlib, io
        for nonce, plan in (('b' * 64, self.plan['planSHA256']), (NONCE, 'c' * 64)):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = tool.main(['run', '--step', 'B1', '--evidence', str(self.root / 'evidence'), '--private-root',
                                  str(self.private), '--work', str(self.root / 'new-work'), '--approve-nonce', nonce,
                                  '--approve-plan', plan])
            self.assertEqual(code, 1)
            self.assertIn('Approval', err.getvalue())
            self.assertFalse((self.root / 'new-work').exists())
        manifest = json.loads((self.root / 'evidence/MANIFEST.json').read_bytes())
        manifest['run'] = 'b' * 64
        (self.root / 'evidence/MANIFEST.json').write_bytes(enc(manifest))
        with self.assertRaisesRegex(tool.Refusal, 'Owner configuration binding'):
            tool.validate(tool.Evidence(self.root / 'evidence'))

    def test_removal_targets_must_be_exact(self):
        self.disposition.run('B1')
        self.fake.guest_remove = lambda nonce: dict(targets=['C:/BimeronFull300'], absent=[True])
        with self.assertRaisesRegex(tool.Refusal, 'Removal targets'):
            self.disposition.run('B2')
        self.assertEqual(self.final()['stoppedAt'], 'B2')

    def test_identity_mismatch_refuses_every_termination(self):
        for step in ('B1', 'B2', 'B3'):
            self.disposition.run(step)
        self.fake.identities[64808]['creationFileTime'] += 10
        with self.assertRaisesRegex(tool.Refusal, 'Creation time mismatch: 64808'):
            self.disposition.run('B4')
        self.assertEqual(self.effects('terminate'), [])
        self.assertEqual(self.final()['status'], 'STOPPED')

    def test_image_or_parent_change_on_handle_refuses(self):
        for step in ('B1', 'B2', 'B3'):
            self.disposition.run(step)
        original = self.fake.terminate

        def terminate(pid, check):
            if pid == 63848:
                check(dict(self.fake.identities[pid], parent=1))
            return original(pid, check)
        self.fake.terminate = terminate
        with self.assertRaisesRegex(tool.Refusal, 'Parent mismatch: 63848'):
            self.disposition.run('B4')
        self.assertEqual([c[1] for c in self.effects('terminate')], [55576])

    def test_network_deviation_stops_step(self):
        self.fake.deviate_after = 3
        self.disposition.run('B1')
        with self.assertRaisesRegex(tool.Refusal, 'deviation during B2'):
            self.disposition.run('B2')
        self.assertEqual(self.final()['stoppedAt'], 'B2')
        with self.assertRaises(tool.Refusal):
            self.disposition.run('B3')
        self.assertEqual(self.effects('ssh'), [])

    def test_guest_readback_after_b1_must_be_clean(self):
        self.fake.states[1] = guest_state(**dict(DONE, udp=[dict(port=500)]))
        with self.assertRaisesRegex(tool.Refusal, 'UDP 500/4500'):
            self.disposition.run('B1')
        self.fake.states = []

    def test_sink_receipt_and_baseline_required(self):
        self.disposition.run('B1')
        self.disposition.run('B2')
        original = self.fake.ssh

        def ssh(argv, data):
            if argv[-1] == 'sudo ethtool -k uplink':
                return b'tx: off\n'
            return original(argv, data)
        self.fake.ssh = ssh
        with self.assertRaisesRegex(tool.Refusal, 'ethtool differs: uplink'):
            self.disposition.run('B3')
        self.assertEqual(self.final()['stoppedAt'], 'B3')

    # ---- r6: capture stop wait ---------------------------------------------
    def health_reads(self):
        return [c for c in self.effects('ssh') if c[1].endswith('health.json')]

    def run_until_b3(self):
        self.disposition.run('B1')
        self.disposition.run('B2')

    def test_capture_stop_polls_until_exit_code(self):
        self.run_until_b3()
        self.fake.null_polls = 3
        self.disposition.run('B3')
        self.assertEqual(len(self.health_reads()), 1 + 4)
        self.assertEqual(self.fake.sleeps, [tool.HEALTH_POLL_SECONDS] * 4)
        polls = sorted(n.name for n in (self.work / 'journal').iterdir() if 'read-health-poll' in n.name)
        self.assertEqual(len(polls), 4)

    def test_capture_stop_timeout_stops_with_evidence(self):
        self.run_until_b3()
        self.fake.null_polls = 10 ** 6
        with self.assertRaisesRegex(tool.Refusal, 'still null 30 s after stop'):
            self.disposition.run('B3')
        self.assertEqual(len(self.health_reads()), 1 + tool.HEALTH_POLL_LIMIT)
        self.assertEqual(len(self.fake.sleeps), tool.HEALTH_POLL_LIMIT)
        polls = [n for n in (self.work / 'journal').iterdir() if 'read-health-poll' in n.name]
        self.assertEqual(len(polls), tool.HEALTH_POLL_LIMIT)
        self.assertEqual((self.final()['status'], self.final()['stoppedAt']), ('STOPPED', 'B3'))
        self.assertFalse([c for c in self.effects('ssh') if 'systemctl stop' in c[1]])

    def test_capture_nonzero_exit_code_stops(self):
        self.run_until_b3()
        self.fake.exit_code = 1
        with self.assertRaisesRegex(tool.Refusal, 'ExitCode 0'):
            self.disposition.run('B3')
        self.assertEqual(len(self.health_reads()), 2)

    # ---- r6: network comparison and proof persistence -------------------------
    def test_dns_flap_is_journaled_not_compared(self):
        self.fake.dns_after = [{'InterfaceIndex': 24, 'ServerAddresses': ['fe80::1']}]
        self.disposition.run('B1')
        record = [n for n in (self.work / 'journal').iterdir() if n.name.endswith('network-B1-dns.json')]
        self.assertEqual(len(record), 1)
        self.assertEqual(json.loads(record[0].read_bytes())['value'], dict(equal=False, compared=False))
        after = [n for n in (self.work / 'journal').iterdir() if n.name.endswith('network-B1-after.json')][0]
        self.assertEqual(json.loads(after.read_bytes())['value']['dns'], self.fake.dns_after)
        self.assertTrue((self.work / 'steps/B1.proven.json').exists())

    def test_wireguard_adapter_state_change_stops(self):
        self.fake.network['adapters'] = [{'Name': 'wg', 'InterfaceDescription': 'WireGuard Tunnel', 'Status': 'Up'}]
        original = self.fake.host_network

        def host_network():
            value = original()
            if len(self.effects('network')) == 2:
                return dict(value, adapters=[dict(value['adapters'][0], Status='Disconnected')])
            return value
        self.fake.host_network = host_network
        with self.assertRaisesRegex(tool.Refusal, 'deviation during B1'):
            self.disposition.run('B1')

    def test_performed_proof_persisted_before_network_deviation(self):
        self.fake.deviate_after = 3
        self.disposition.run('B1')
        with self.assertRaisesRegex(tool.Refusal, 'deviation during B2'):
            self.disposition.run('B2')
        names = sorted(n.name for n in (self.work / 'journal').iterdir())
        performed = [n for n in names if n.endswith('B2-performed.json')]
        self.assertEqual(len(performed), 1)
        after = [n for n in names if n.endswith('network-B2-after.json')][0]
        self.assertLess(names.index(performed[0]), names.index(after))
        value = json.loads((self.work / 'journal' / performed[0]).read_bytes())['value']
        self.assertEqual(value['removed']['targets'][0], 'C:/BimeronFull300/' + NONCE)

    # ---- r6: work directory validated before B1 ---------------------------------
    def main_run(self, step, work):
        import contextlib, io
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = tool.main(['run', '--step', step, '--evidence', str(self.root / 'evidence'), '--private-root',
                              str(self.private), '--work', str(work), '--approve-nonce', NONCE,
                              '--approve-plan', self.plan['planSHA256']])
        return code, err.getvalue()

    def patch_sddl(self, value):
        original = tool.read_sddl
        tool.read_sddl = lambda path: value
        self.addCleanup(setattr, tool, 'read_sddl', original)

    def junction(self, link, target):
        import subprocess
        target.mkdir(parents=True, exist_ok=True)
        subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(target)], check=True, capture_output=True)
        self.addCleanup(lambda: os.path.lexists(link) and os.rmdir(link))

    def test_work_under_junction_refused_before_b1(self):
        self.patch_sddl(SAFE_SDDL)
        self.junction(self.root / 'link', self.root / 'real')
        code, err = self.main_run('B1', self.root / 'link' / 'disposition')
        self.assertEqual(code, 1)
        self.assertIn('Work ancestor is a reparse point', err)
        self.assertEqual(list((self.root / 'real').iterdir()), [])

    def test_work_parent_broad_write_acl_refused_before_b1(self):
        self.patch_sddl('O:BAG:SYD:(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;BU)')
        code, err = self.main_run('B1', self.root / 'new-work')
        self.assertEqual(code, 1)
        self.assertIn('writable by broad principals', err)
        self.assertFalse((self.root / 'new-work').exists())

    def test_existing_work_with_inner_reparse_refused(self):
        self.patch_sddl(SAFE_SDDL)
        self.junction(self.work / 'journal-link', self.root / 'elsewhere')
        code, err = self.main_run('B2', self.work)
        self.assertEqual(code, 1)
        self.assertIn('Reparse point inside work directory', err)
        code, err = self.main_run('B1', self.work)
        self.assertIn('already exists', err)

    def test_sddl_write_detection(self):
        self.assertEqual(tool.broad_write_aces(SAFE_SDDL), [])
        self.assertEqual(tool.broad_write_aces('D:(A;OICIIO;GA;;;AU)(A;;0x1200a9;;;BU)(A;;FR;;;WD)'), [])
        self.assertEqual(len(tool.broad_write_aces('D:(A;;LC;;;AU)(A;OICI;FW;;;S-1-1-0)')), 2)
        with self.assertRaisesRegex(tool.Refusal, 'Unknown ACE rights'):
            tool.broad_write_aces('D:(A;;KA;;;BU)')

    # ---- r6: held owner quiescence ----------------------------------------------
    def test_new_resident_request_refuses_b1(self):
        (self.private / 'guest-control' / ('resident-request-%020d.json' % 3)).write_bytes(b'{}')
        with self.assertRaisesRegex(tool.Refusal, 'not quiescent before B1'):
            self.disposition.run('B1')
        self.assertEqual([c for c in self.fake.calls if c[0] not in ('guest-control',)], [])
        self.assertEqual(self.final()['stoppedAt'], 'B1')

    def test_changed_resident_response_refuses_b2(self):
        self.disposition.run('B1')
        (self.private / 'guest-control' / ('resident-response-%020d.json' % 2)).write_bytes(b'{"state":"Collected"}')
        with self.assertRaisesRegex(tool.Refusal, 'not quiescent before B2'):
            self.disposition.run('B2')
        self.assertEqual(self.effects('remove'), [])

    def test_unrelated_guest_control_logs_do_not_count(self):
        (self.private / 'guest-control' / 'resident.stdout').write_bytes(b'more log\n')
        self.disposition.run('B1')

    # ---- r6: B2 parents must not be reparse points --------------------------------
    def test_guest_remove_checks_parent_reparse_chain(self):
        import subprocess
        source = (HERE / 'dispose-held-run.ps1').read_text(encoding='utf-8')
        remove = source[source.index('$remove={'):source.index('$session=Open-OwnerSession')]
        check = remove.index("foreach($parent in @('C:/BimeronFull300','C:/BimeronStep10Probe')){if(Test-Path -LiteralPath $parent){Assert-NoReparseChain $parent}}")
        self.assertLess(check, remove.index('Remove-Item'))
        self.junction(self.root / 'jn', self.root / 'jt')
        (self.root / 'jt' / 'BimeronFull300').mkdir()
        def quote(path):
            return "'" + str(path).replace("'", "''") + "'"
        script = ("$ErrorActionPreference='Stop';$t=$null;$e=$null;"
                  "$ast=[System.Management.Automation.Language.Parser]::ParseFile(%s,[ref]$t,[ref]$e);"
                  "$f=$ast.FindAll({param($n)$n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-NoReparseChain'},$true);"
                  "if(@($f).Count -ne 1){throw 'function count'};. ([scriptblock]::Create($f[0].Extent.Text));"
                  "Assert-NoReparseChain %s;'clean';Assert-NoReparseChain %s;'unsafe-accepted'") % (
                      quote(HERE / 'dispose-held-run.ps1'), quote(self.root / 'jt' / 'BimeronFull300'),
                      quote(self.root / 'jn' / 'BimeronFull300'))
        completed = subprocess.run([tool.POWERSHELL, '-NoProfile', '-NonInteractive', '-Command', script],
                                   stdin=subprocess.DEVNULL, capture_output=True, timeout=120,
                                   env=tool.powershell_environment())
        out = completed.stdout + completed.stderr
        self.assertIn(b'clean', out)
        self.assertIn(b'Reparse ancestor', out)
        self.assertNotIn(b'unsafe-accepted', out)

    # ---- r6: leftover processes after B4 ------------------------------------------
    def leftover(self, pid, parent, created, cmd):
        self.fake.scan_rows.append(dict(pid=pid, parent=parent, name='ssh.exe', image=tool.SSH,
                                        creationFileTime=created, commandLine=cmd))
        self.fake.identities[pid] = dict(pid=pid, creationFileTime=created, image=tool.SSH, parent=parent)

    def run_until_b4(self):
        for step in ('B1', 'B2', 'B3'):
            self.disposition.run(step)

    def test_verified_child_leftover_terminated_in_b4(self):
        self.run_until_b4()
        self.leftover(68840, 55576, int(TIMES[55576][1]) + 5, tool.SSH + ' -F none status ' + NONCE)
        self.disposition.run('B4')
        self.assertEqual([c[1] for c in self.effects('terminate')], [55576, 63848, 64808, 62144, 68840])
        self.assertEqual(self.final()['status'], 'DISPOSED')
        self.assertEqual(len(self.effects('scan')), 2)

    def test_own_process_chain_is_not_a_leftover(self):
        self.run_until_b4()
        self.disposition.run('B4')
        self.assertEqual(len(self.effects('scan')), 1)
        self.assertEqual(len(self.effects('terminate')), 4)

    def test_unrelated_leftover_reported_and_stops(self):
        self.run_until_b4()
        self.leftover(9100, 4, 10 ** 18, 'python ' + ADMISSION + '\\x.py')
        with self.assertRaisesRegex(tool.Refusal, r'Unverified leftover run processes: \[9100\]'):
            self.disposition.run('B4')
        self.assertNotIn(9100, [c[1] for c in self.effects('terminate')])
        self.assertEqual(self.final()['stoppedAt'], 'B4')
        scan = [n for n in (self.work / 'journal').iterdir() if n.name.endswith('leftover-scan.json')]
        self.assertEqual(json.loads(scan[0].read_bytes())['value']['found'][0]['pid'], 9100)

    def test_leftover_older_than_parent_pid_reuse_refused(self):
        self.run_until_b4()
        self.leftover(68840, 55576, int(TIMES[55576][1]) - 5, 'ssh ' + NONCE)
        with self.assertRaisesRegex(tool.Refusal, 'Unverified leftover'):
            self.disposition.run('B4')
        self.assertNotIn(68840, [c[1] for c in self.effects('terminate')])

    # ---- r7 ----------------------------------------------------------------------
    def journal_value(self, suffix):
        names = [n for n in (self.work / 'journal').iterdir() if n.name.endswith(suffix)]
        self.assertEqual(len(names), 1, suffix)
        return json.loads(names[0].read_bytes())['value']

    @unittest.skipUnless(sys.platform == 'win32', 'Windows ACL reader')
    def test_real_read_sddl_returns_sddl(self):
        sddl = tool.read_sddl(self.work)
        self.assertRegex(sddl, r'^O:.*D:')
        tool.broad_write_aces(sddl)
        spaced = self.root / "a dir with 'quote' $x"
        spaced.mkdir()
        self.assertIn('D:', tool.read_sddl(spaced))

    @unittest.skipUnless(sys.platform == 'win32', 'Windows ACL reader')
    def test_validate_work_with_real_reader(self):
        target = self.root / 'disposition-new'
        tool.validate_work(target, 'B1')
        self.assertFalse(target.exists())
        tool.validate_work(self.work, 'B2')
        with self.assertRaisesRegex(tool.Refusal, 'already exists'):
            tool.validate_work(self.work, 'B1')

    def test_read_sddl_passes_path_by_environment_only(self):
        import subprocess
        seen = {}

        def run(argv, **kwargs):
            seen.update(argv=argv, env=kwargs['env'])
            return subprocess.CompletedProcess(argv, 0, b'O:BAD:(A;;FA;;;SY)\r\n', b'')
        original = tool.subprocess.run
        tool.subprocess.run = run
        self.addCleanup(setattr, tool.subprocess, 'run', original)
        self.assertEqual(tool.read_sddl(self.work), 'O:BAD:(A;;FA;;;SY)')
        self.assertEqual(seen['argv'][-2], '-Command')
        self.assertNotIn(str(self.work), seen['argv'])
        self.assertEqual(seen['env']['BIMERON_ACL_PATH'], str(self.work))

    def test_link_speed_change_is_journaled_not_compared(self):
        original = self.fake.host_network

        def host_network():
            value = original()
            if len(self.effects('network')) == 2:
                return dict(value, adapterLinkSpeeds=[{'InterfaceGuid': '{1}', 'LinkSpeed': '100 Mbps'}])
            return value
        self.fake.host_network = host_network
        self.disposition.run('B1')
        self.assertEqual(self.journal_value('network-B1-link-speed.json'), dict(equal=False, compared=False))
        self.assertTrue((self.work / 'steps/B1.proven.json').exists())

    def test_helper_does_not_compare_link_speed(self):
        source = (HERE / 'dispose-held-run.ps1').read_text(encoding='utf-8')
        adapters = [l for l in source.splitlines() if l.strip().startswith('adapters=')]
        self.assertEqual(len(adapters), 1)
        self.assertNotIn('LinkSpeed', adapters[0])
        self.assertIn('Status', adapters[0])
        self.assertIn('adapterLinkSpeeds', source)
        self.assertNotIn('adapterLinkSpeeds', tool.STRICT_NETWORK_FIELDS)
        self.assertIn('adapters', tool.STRICT_NETWORK_FIELDS)

    def test_leftover_gone_before_verify_is_journaled(self):
        self.run_until_b4()
        self.leftover(68840, 55576, int(TIMES[55576][1]) + 5, 'ssh ' + NONCE)
        self.fake.gone.add(68840)
        self.disposition.run('B4')
        self.assertEqual(self.journal_value('leftover-gone-68840.json')['stage'], 'verify')
        self.assertNotIn(68840, [c[1] for c in self.effects('terminate')])
        self.assertEqual(self.final()['status'], 'DISPOSED')

    def test_leftover_gone_before_terminate_is_journaled(self):
        self.run_until_b4()
        self.leftover(68840, 55576, int(TIMES[55576][1]) + 5, 'ssh ' + NONCE)
        self.fake.gone_on_terminate.add(68840)
        self.disposition.run('B4')
        self.assertEqual(self.journal_value('leftover-gone-68840.json')['stage'], 'terminate')
        self.assertEqual(self.final()['status'], 'DISPOSED')

    def test_rescan_ignores_reused_pid_with_new_creation_time(self):
        self.run_until_b4()
        created = int(TIMES[55576][1]) + 5
        self.leftover(68840, 55576, created, 'ssh ' + NONCE)
        self.fake.extra_rows.append(dict(pid=68840, parent=1, name='notepad.exe', image=r'C:\notepad.exe',
                                         creationFileTime=created + 10 ** 7, commandLine='notepad'))
        self.disposition.run('B4')
        self.assertEqual(self.journal_value('leftover-rescan.json'), dict(remaining=[]))
        self.assertEqual(self.final()['status'], 'DISPOSED')

    def test_rescan_same_pid_and_creation_stops(self):
        self.run_until_b4()
        created = int(TIMES[55576][1]) + 5
        self.leftover(68840, 55576, created, 'ssh ' + NONCE)
        # Same identity at CIM microsecond precision.
        self.fake.extra_rows.append(dict(pid=68840, parent=55576, name='ssh.exe', image=tool.SSH,
                                         creationFileTime=created // 10 * 10, commandLine='other'))
        with self.assertRaisesRegex(tool.Refusal, r'still present: \[68840\]'):
            self.disposition.run('B4')

    def test_helper_refuses_bad_nonce_or_driver_before_any_session(self):
        import subprocess
        source = (HERE / 'dispose-held-run.ps1').read_text(encoding='utf-8')
        self.assertNotIn(NONCE, source)
        self.assertLess(source.index("throw 'Fixed driver path absent'"), source.index('$session=Open-OwnerSession'))
        for nonce, expected in (('B' * 64, b'Run nonce format'), ('b' * 64, b'Fixed driver path absent')):
            completed = subprocess.run([tool.POWERSHELL, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                        '-File', str(HERE / 'dispose-held-run.ps1'), '-Step', 'guest-remove',
                                        '-RunNonce', nonce, '-Driver', str(self.root / 'absent-driver')],
                                       stdin=subprocess.DEVNULL, capture_output=True, timeout=120,
                                       env=tool.powershell_environment())
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(expected, completed.stdout + completed.stderr)


# ---- generic held runs: 9de2f235-shaped fixture (run completed B1/B3 itself) -------
NONCE9 = '9de2f23566dd6154545ee9ef9f6248810cc300a7fec8a05825f8a58beeb7810e'
INSTANCE9 = '{06D65EB1-ABA2-445F-BB33-828F6AED6E1E}'
# (pid, name, parent, created, creationFileTime or None, marker)
TREE9 = ((80928, 'python.exe', 81152, '2026-11-05T23:13:44.9249210Z', '134383940249249215', 'preparation.py'),
         (80044, 'python.exe', 80928, '2026-11-05T23:13:48.2437160Z', '134383940282437166', 'pinned_watcher.py'),
         (33356, 'conhost.exe', 80928, '2026-11-05T23:13:44.9449450Z', None, 'conhost.exe 0x4'),
         (76860, 'conhost.exe', 80044, '2026-11-05T23:13:48.2479450Z', None, 'conhost.exe 0x4'))
RECEIPT9 = None


def receipt(nonce):
    import sink_contract
    return dict(schema='fresh-sink-exit-v1', nonce=nonce, unit='step10-prep-' + nonce + '.service',
                contractSHA256=sink_contract.CONTRACT_SHA256, invocationId='5' * 32, result='success',
                exitCode='killed', exitStatus='TERM')


def build_done_evidence(root, nonce=NONCE9, root_name=None, extra=None, drop=(), tree=TREE9, dirs='True'):
    """Evidence of a run whose own endpoint sealed/released the guest and retired the observer."""
    sys.path.insert(0, str(tool.DRIVER))
    import sink_contract
    files = {}
    p = 'host/private-root/'
    ot = p + 'owner-transport/'
    private = root / 'held' / (root_name or ('capture-prep-' + nonce))
    config = enc(dict(schema='full300-owner-config-v1', nonce=nonce, taskName='BimeronFull300Owner-' + nonce))
    seal = enc(dict(schema='full300-owner-command-v1', nonce=nonce, configSHA256=sha(config), seq=1,
                    op='seal-no-launch', body={}))
    no_launch = enc(dict(schema='full300-no-launch-v1', nonce=nonce, configSHA256=sha(config),
                         supervisorOnceSHA256='f' * 64, sealCommandSHA256=sha(seal), launchAttempted=False, sealed=True))
    exit_raw = enc(dict(schema='full300-owner-command-v1', nonce=nonce, configSHA256=sha(config), seq=2,
                        op='exit-supervisor', body=dict(noLaunch=dict(name='no-launch.json', sha256=sha(no_launch),
                                                                       length=len(no_launch)))))
    ready = enc(dict(schema='full300-supervisor-exit-v1', nonce=nonce, configSHA256=sha(config),
                     supervisorOnceSHA256='f' * 64, exitCommandSHA256=sha(exit_raw), proofSHA256=sha(no_launch),
                     reason='sealed-no-launch'))

    def response(seq, command, state, refs):
        return enc(dict(schema='full300-owner-response-v1', nonce=nonce, configSHA256=sha(config), seq=seq,
                        commandSHA256=sha(command), outcome='accepted', state=state, owner=None, error=None,
                        refs=[dict(name=n, sha256=sha(r), length=len(r)) for n, r in refs]))
    files.update({ot + 'config.json': config, ot + 'commands/00000001.json': seal, ot + 'commands/00000002.json': exit_raw,
                  ot + 'task-instance.json': enc(dict(instanceGuid=INSTANCE9)),
                  ot + 'task-registration.json': b'{"xml":"<Task/>"}',
                  ot + 'proofs/no-launch.json': no_launch, ot + 'proofs/supervisor-exit-ready.json': ready,
                  ot + 'responses/00000001.json': response(1, seal, 'SEALED_NO_LAUNCH', [('no-launch.json', no_launch)]),
                  ot + 'responses/00000002.json': response(2, exit_raw, 'EXIT_READY',
                                                           [('no-launch.json', no_launch), ('supervisor-exit-ready.json', ready)]),
                  ot + 'task-final.json': enc(dict(state=3, instanceGuids=[], instanceGuid=INSTANCE9, lastTaskResult=0)),
                  p + 'nonce.txt': nonce.encode()})
    ssh = [tool.SSH, '-F', 'none', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', 'lab@192.0.2.9']
    files[p + 'host-supervisor-config.json'] = enc(dict(nonce=nonce, capture=IDENTITY,
        query=ssh + ['sudo python3 ' + CAPTURE + ' status ' + nonce]))
    for seq in (1, 2):
        files[p + 'guest-control/resident-request-%020d.json' % seq] = enc(dict(sequence=seq, operation='x'))
        files[p + 'guest-control/resident-response-%020d.json' % seq] = enc(dict(sequence=seq, state='Collected'))
    files[p + 'guest-control/resident-finished.json'] = b'{}'
    journals = {}
    processes = []
    for pid, name, parent, created, exact, marker in tree:
        if marker == 'pinned_watcher.py':
            cmd = 'python.exe -I -S pinned_watcher.py --config ' + str(private) + '\\host-supervisor-config.json'
            journals['journalContainment'] = dict(pid=pid, creationFileTime=exact)
        elif marker == 'preparation.py':
            cmd = 'python.exe -I -S preparation.py --configuration C:\\lab\\config.json'
            journals['journalOwner'] = dict(pid=pid, creationFileTime=exact)
        else:
            cmd = marker if name == 'conhost.exe' else marker + ' ' + nonce
        processes.append(dict(pid=pid, parent=parent, name=name, created=created,
                              exe=PYTHON if name == 'python.exe' else (PS if name == 'powershell.exe' else r'C:\WINDOWS\system32\conhost.exe'),
                              cmd=cmd))
    files['host/process-tree.json'] = enc(dict(schema='host-process-tree-v1', processes=processes, **journals))
    owner = [j for k, j in journals.items() if k == 'journalOwner'][0]
    watcher = journals['journalContainment']
    files[p + 'owner-created.json'] = enc(dict(binding=dict(nonce=nonce, owner=owner, containmentOwner=watcher)))
    baseline = enc(dict(nft=NFT, topology=TOPOLOGY, labnetFeatures=b64(b'rx: on\n'), uplinkFeatures=b64(b'tx: on\n'),
                        services=SERVICES, guest={}, absence={}, git={}))
    files['host/admission/baseline.json'] = baseline
    files['host/admission/config.json'] = enc(dict(baseline=dict(sha256=sha(baseline)), admissionRoot=ADMISSION))
    files['guest/guest-state.json'] = enc(dict(
        ownerTasks=[], taskState="ABSENT: No MSFT_ScheduledTask objects found",
        dirsExist=['C:/BimeronFull300/%s=%s' % (nonce, dirs), 'C:/BimeronStep10Probe/%s=%s' % (nonce, dirs)],
        processes=[dict(pid=4, name='System', cmd=None)], remoteListing=[]))
    confirmation = sink_contract.retirement_commands(nonce, CAPTURE)['confirmation']
    unit = 'step10-prep-' + nonce + '.service'
    files.update({'observer/run-health.json': enc(dict(Nonce=nonce, Healthy=False, ExitCode=0, Identity=IDENTITY)),
                  'observer/run-cleanup-confirmed.json': confirmation,
                  'observer/run-sink-exit.json': enc(receipt(nonce)),
                  'observer/run-identity.json': enc(IDENTITY), 'observer/run-ingress.pcap': PCAP,
                  'observer/run-capture.log': b'listening on labnet\n0 packets dropped by kernel\n',
                  'observer/systemctl-list-units.txt': b'',
                  'observer/systemctl-status.txt.stderr': ('Unit %s could not be found.\n' % unit).encode(),
                  'observer/nft.json': enc(NFT), 'observer/links.json': enc(TOPOLOGY['links']),
                  'observer/addresses.json': enc(TOPOLOGY['addresses']), 'observer/routes.json': enc(TOPOLOGY['routes']),
                  'observer/labnetFeatures.txt': b'rx: on\n', 'observer/uplinkFeatures.txt': b'tx: on\n'})
    files.update(extra or {})
    for name in drop:
        del files[name]
    entries = []
    for relative, raw in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        entries.append(dict(path=relative, size=len(raw), sha256=sha(raw)))
    (root / 'MANIFEST.json').write_bytes(enc(dict(schema='evidence-manifest-v1', run=nonce, files=entries)))
    for relative, raw in files.items():
        if relative.startswith(p):
            target = private / relative[len(p):]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
    return private


class DoneFake(Fake):
    """Live state after the run completed B1/B3 itself: clean guest, retired observer."""

    def __init__(self, private, nonce=NONCE9, tree=TREE9):
        super().__init__(private)
        self.nonce = nonce
        clean = dict(DONE, nonce=nonce, tasks=[], processes=[])
        self.states = [guest_state(**clean), guest_state(**dict(clean, rootExists=False, probeExists=False))]
        self.identities = {pid: dict(pid=pid, creationFileTime=int(exact) if exact else tool.filetime(created) + 3,
                                     image=PYTHON if name == 'python.exe' else PS, parent=parent)
                           for pid, name, parent, created, exact, _ in tree}
        self.live_exit = 0
        self.live_receipt = receipt(nonce)

    def guest_remove(self, nonce):
        self.calls.append(('remove', nonce))
        return dict(targets=['C:/BimeronFull300/' + nonce, 'C:/BimeronStep10Probe/' + nonce], absent=[True, True])

    def ssh(self, argv, data):
        command = argv[-1]
        self.calls.append(('ssh', command))
        assert argv[:3] == [tool.SSH, '-F', 'none']
        assert command.startswith(('sudo cat ', 'sudo systemctl list-units', 'sudo nft -j list', 'sudo ethtool -k ', 'ip -j ')), command
        if command.endswith('cleanup-confirmed.json'):
            import sink_contract
            return sink_contract.retirement_commands(self.nonce, CAPTURE)['confirmation']
        if command.endswith('health.json'):
            return enc(dict(Nonce=self.nonce, ExitCode=self.live_exit))
        if command.endswith('sink-exit.json'):
            return enc(self.live_receipt)
        if command.startswith('sudo systemctl list-units'):
            return b''
        if command.endswith('ingress.pcap'):
            return PCAP
        if command.endswith('capture.log'):
            return b'0 packets dropped by kernel\n'
        if command.endswith('identity.json'):
            return enc(IDENTITY)
        return Fake.ssh(self, argv[:-1] + [command], data)


def guest_state9(**changes):
    return guest_state(**dict(dict(DONE, nonce=NONCE9, tasks=[], processes=[]), **changes))


class GenericHeldRunTests(unittest.TestCase):
    def setUp(self):
        self.root = TEMP / ('dhg-' + uuid.uuid4().hex[:8])
        self.root.mkdir(parents=True)
        self.evidence = self.root / 'evidence'
        self.work = self.root / 'work'
        self.work.mkdir()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def make(self, **kwargs):
        self.private = build_done_evidence(self.evidence, **kwargs)
        self.plan = tool.validate(tool.Evidence(self.evidence))
        self.fake = DoneFake(self.private)
        self.disposition = tool.Disposition(self.plan, self.fake, tool.Journal(self.work, NONCE9))
        return self.plan

    def effects(self, kind):
        return [c for c in self.fake.calls if c[0] == kind]

    def final(self):
        return json.loads((self.work / 'final-record.json').read_bytes())

    def test_9de_shaped_plan_modes_and_processes(self):
        plan = self.make()
        self.assertEqual(plan['modes'], dict(B1='confirm', B2='act', B3='confirm', B4='act'))
        self.assertEqual([(p['role'], p['pid'], p['creationFileTime']) for p in plan['processes']],
                         [('watcher', 80044, 134383940282437166), ('owner', 80928, 134383940249249215)])
        self.assertEqual(plan['privateRoot'], str(self.private))
        summary = tool.summary(plan)
        self.assertEqual(summary['actions']['B4'], 'terminate watcher 80044 -> owner 80928, then leftover scan')
        self.assertEqual(plan['planSHA256'], sha(tool.canonical_json(summary)))

    def test_9de_shaped_full_run_confirms_without_resending(self):
        self.make()
        for step in tool.STEPS:
            self.disposition.run(step)
        self.assertEqual(self.effects('deliver'), [])
        self.assertEqual([c[1] for c in self.effects('remove')], [NONCE9])
        sent = [c[1] for c in self.effects('ssh')]
        self.assertFalse([c for c in sent if c == 'sudo python3 -' or ' stop ' in c or 'systemctl stop' in c])
        self.assertEqual([c[1] for c in self.effects('terminate')], [80044, 80928])
        final = self.final()
        self.assertEqual((final['status'], final['settled'], final['normalCleanup'], final['label']),
                         ('DISPOSED', False, False, tool.LABEL))
        self.assertEqual(final['modes'], dict(B1='confirm', B2='act', B3='confirm', B4='act'))
        names = sorted(n.name for n in (self.work / 'journal').iterdir())
        for event in ('B1-confirmed', 'B2-performed', 'B3-confirmed', 'B4-performed'):
            self.assertEqual(len([n for n in names if n.endswith(event + '.json')]), 1, event)
        self.assertFalse((self.work / 'owner-transport').exists())
        self.assertEqual((self.work / 'observer-archive/ingress.pcap').read_bytes(), PCAP)

    def test_b1_confirm_refuses_live_supervisor_without_delivery(self):
        self.make()
        self.fake.states[0] = guest_state9(processes=[dict(pid=1, commandLine='owner-supervisor.ps1 ' + NONCE9)])
        with self.assertRaisesRegex(tool.Refusal, 'Guest supervisor still running'):
            self.disposition.run('B1')
        self.assertEqual(self.effects('deliver'), [])
        self.assertEqual(self.final()['stoppedAt'], 'B1')

    def test_b1_confirm_refuses_changed_private_response(self):
        self.make()
        (self.private / 'owner-transport/responses/00000002.json').write_bytes(b'{"changed":1}')
        with self.assertRaisesRegex(tool.Refusal, 'differs from evidence: owner-transport/responses/00000002.json'):
            self.disposition.run('B1')
        self.assertEqual(self.effects('deliver'), [])
        self.assertEqual(self.effects('guest-state'), [])

    def test_b3_confirm_refuses_running_capture_without_stop(self):
        self.make()
        self.disposition.run('B1')
        self.disposition.run('B2')
        self.fake.live_exit = None
        with self.assertRaisesRegex(tool.Refusal, 'ExitCode 0'):
            self.disposition.run('B3')
        self.assertFalse([c for c in self.effects('ssh') if ' stop ' in c[1] or c[1] == 'sudo python3 -'])

    def test_b3_confirm_refuses_different_sink_receipt(self):
        self.make()
        self.disposition.run('B1')
        self.disposition.run('B2')
        self.fake.live_receipt = dict(receipt(NONCE9), invocationId='6' * 32)
        with self.assertRaisesRegex(tool.Refusal, 'Sink receipt differs from evidence'):
            self.disposition.run('B3')

    def test_b2_confirm_when_evidence_shows_directories_absent(self):
        plan = self.make(dirs='False')
        self.assertEqual(plan['modes']['B2'], 'confirm')
        self.disposition.run('B1')
        self.disposition.run('B2')
        self.assertEqual(self.effects('remove'), [])

    def test_partial_b1_evidence_is_refused(self):
        with self.assertRaisesRegex(tool.Refusal, 'B1 partly completed'):
            self.make(drop=('host/private-root/owner-transport/responses/00000002.json',))

    def test_partial_b3_evidence_is_refused(self):
        with self.assertRaisesRegex(tool.Refusal, 'B3 partly completed'):
            self.make(drop=('observer/run-sink-exit.json',))

    def test_b3_evidence_must_equal_baseline(self):
        with self.assertRaisesRegex(tool.Refusal, 'ethtool differs: uplink'):
            self.make(extra={'observer/uplinkFeatures.txt': b'tx: off\n'})

    def test_generic_process_list_role_order_and_unknown_child(self):
        tree = TREE9 + ((81000, 'powershell.exe', 80928, '2026-11-05T23:14:00.0000000Z', None, 'resident-main.ps1'),
                        (80990, 'powershell.exe', 80928, '2026-11-05T23:14:01.0000000Z', None, 'resident-main.ps1'),
                        (81010, 'powershell.exe', 80928, '2026-11-05T23:14:02.0000000Z', None, 'prepare-task.ps1'),
                        (81020, 'ssh.exe', 80044, '2026-11-05T23:14:03.0000000Z', None, 'ssh.exe status'))
        plan = self.make(tree=tree)
        self.assertEqual([(p['role'], p['pid']) for p in plan['processes']],
                         [('watcher', 80044), ('resident', 80990), ('resident', 81000), ('task-helper', 81010),
                          ('owner', 80928)])
        self.fake = DoneFake(self.private, tree=tree)
        self.disposition = tool.Disposition(self.plan, self.fake, tool.Journal(self.work, NONCE9))
        for step in tool.STEPS:
            self.disposition.run(step)
        self.assertEqual([c[1] for c in self.effects('terminate')], [80044, 80990, 81000, 81010, 80928])
        shutil.rmtree(self.evidence)
        with self.assertRaisesRegex(tool.Refusal, 'role unknown or ambiguous: 81030'):
            self.make(tree=tree + ((81030, 'cmd.exe', 80928, '2026-11-05T23:14:04.0000000Z', None, 'cmd /c x'),))

    def test_owner_claim_must_match_process_tree(self):
        with self.assertRaisesRegex(tool.Refusal, 'Owner claim / process tree identity: watcher'):
            self.make(extra={'host/private-root/owner-created.json': enc(dict(binding=dict(
                nonce=NONCE9, owner=dict(pid=80928, creationFileTime='134383940249249215'),
                containmentOwner=dict(pid=80044, creationFileTime='1'))))})

    def test_private_root_both_naming_schemes_and_binding(self):
        plan = self.make()
        tool.check_private_root(plan, self.private)
        with self.assertRaisesRegex(tool.Refusal, 'Held private root path'):
            tool.check_private_root(plan, self.private.parent / ('other-' + NONCE9))
        shutil.rmtree(self.evidence)
        shutil.rmtree(self.root / 'evidence', ignore_errors=True)
        short = 'cp-' + NONCE9[:16]
        plan = self.make(root_name=short, extra={'host/private-root/run-identity.json': enc(dict(
            schema='fresh-admin-run-identity-v1', nonce=NONCE9, rootName=short))})
        self.assertEqual(pathlib.Path(plan['privateRoot']).name, short)
        tool.check_private_root(plan, self.private)
        (self.private / 'run-identity.json').write_bytes(enc(dict(nonce='0' * 64, rootName=short)))
        with self.assertRaisesRegex(tool.Refusal, 'run-identity.json'):
            tool.check_private_root(plan, self.private)
        moved = self.root / 'elsewhere' / short
        moved.mkdir(parents=True)
        with self.assertRaisesRegex(tool.Refusal, 'differs from the watcher root'):
            tool.check_private_root(plan, moved)

    def test_dry_run_reports_plan_digest_and_run_requires_it(self):
        import contextlib, io
        self.make()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(tool.main(['dry-run', '--evidence', str(self.evidence)]), 0)
        report = json.loads(out.getvalue())
        self.assertEqual((report['planSHA256'], report['modes']['B1']), (self.plan['planSHA256'], 'confirm'))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = tool.main(['run', '--step', 'B1', '--evidence', str(self.evidence), '--private-root',
                              str(self.private), '--work', str(self.root / 'new-work'), '--approve-nonce', NONCE9])
        self.assertEqual(code, 1)
        self.assertIn('--approve-plan', err.getvalue())
        self.assertFalse((self.root / 'new-work').exists())


# ---- f8956ea0-shaped fixture: no seal reserved, transient monitor ssh, resident without journal FILETIME ----
INSTANCEF = '{3CAA5269-456B-42A9-BDB7-10A2FB80680B}'
# (pid, name, parent, created, creationFileTime or None, marker or None for an unreadable row)
TREEF = ((66184, 'python.exe', 47288, '2026-11-06T00:15:36.0417790Z', '134383977360417797', 'preparation.py'),
         (71536, 'conhost.exe', 66184, '2026-11-06T00:15:36.0616420Z', None, 'conhost.exe 0x4'),
         (44692, 'python.exe', 66184, '2026-11-06T00:15:39.5835650Z', '134383977395835656', 'pinned_watcher.py'),
         (11128, 'powershell.exe', 66184, '2026-11-06T00:15:40.5862490Z', None, 'resident-main.ps1'),
         (18356, 'ssh.exe', 66184, '2026-11-06T00:17:55.1294460Z', None, None),
         (50540, 'conhost.exe', 18356, '2026-11-06T00:17:55.1311260Z', None, None))


def build_unreserved_evidence(root, tree=TREEF, extra=None, drop=(), mutate=None, utc='2026-11-06T00:17:55.4370667Z'):
    """Evidence of a run held after preflight: supervisor running, no seal ever reserved."""
    files = {}
    p = 'host/private-root/'
    ot = p + 'owner-transport/'
    short = 'cp-' + NONCE[:16]
    private = root / 'held' / short
    config = enc(dict(schema='full300-owner-config-v1', nonce=NONCE, taskName='BimeronFull300Owner-' + NONCE))
    once = enc(dict(nonce=NONCE, sessionId=2, creationFileTime='134383977482073263', configSHA256=sha(config),
                    pid=3672, schema='full300-supervisor-once-v1', elevated=True))
    guest = 'guest/BimeronFull300/' + NONCE + '/transport/'
    files.update({ot + 'config.json': config, ot + 'task-instance.json': enc(dict(instanceGuid=INSTANCEF)),
                  ot + 'task-registration.json': b'{"xml":"<Task/>"}', ot + 'proofs/supervisor-once.json': once,
                  guest + 'config.json': config, guest + 'proofs/supervisor-once.json': once,
                  p + 'nonce.txt': NONCE.encode(),
                  p + 'run-identity.json': enc(dict(schema='fresh-admin-run-identity-v1', nonce=NONCE, rootName=short))})
    ssh = [tool.SSH, '-F', 'none', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', 'lab@192.0.2.9']
    query = ssh + ['sudo python3 ' + CAPTURE + ' status ' + NONCE]
    files[p + 'host-supervisor-config.json'] = enc(dict(nonce=NONCE, capture=IDENTITY, query=query))
    for seq, op, output in ((1, 'principal', b'S-1-5-21-1'), (2, 'preflight', once)):
        request = enc(dict(sequence=seq, mode='submit', operation=op, path='C:\\held\\' + op + '.json',
                           requestSHA256='e' * 64))
        files[p + 'guest-control/resident-request-%020d.json' % seq] = request
        files[p + 'guest-control/resident-reserved-%020d.json' % seq] = request
        files[p + 'guest-control/resident-response-%020d.json' % seq] = enc(dict(
            sequence=seq, state='Collected', output=base64.b64encode(output).decode()))
    journals = {}
    processes = []
    for pid, name, parent, created, exact, marker in tree:
        exe = PYTHON if name == 'python.exe' else PS if name == 'powershell.exe' else r'C:\WINDOWS\system32\conhost.exe'
        if marker == 'pinned_watcher.py':
            cmd = 'python.exe -I -S pinned_watcher.py --config ' + str(private) + '\\host-supervisor-config.json'
            journals['journalContainment'] = dict(pid=pid, creationFileTime=exact)
        elif marker == 'preparation.py':
            cmd = 'python.exe -I -S preparation.py --configuration C:\\lab\\config.json'
            journals['journalOwner'] = dict(pid=pid, creationFileTime=exact)
        elif marker is None:
            exe = cmd = None  # exited or unreadable when the tree was collected
        else:
            cmd = marker if name == 'conhost.exe' else marker + ' -Nonce ' + NONCE
        processes.append(dict(pid=pid, parent=parent, name=name, created=created, exe=exe, cmd=cmd))
    files['host/process-tree.json'] = enc(dict(schema='host-process-tree-v1', processes=processes, **journals,
                                               **({} if utc is None else dict(utc=utc))))
    owner = journals['journalOwner']
    binding = dict(nonce=NONCE, owner=owner, containmentOwner=journals['journalContainment'])
    files[p + 'owner-created.json'] = enc(dict(binding=binding))
    # The owner's own monitor status queries (admin_transport journal records).
    files[p + 'transport-000001.json'] = enc(dict(argv=ssh + ['hostname'], binding=binding, inputSHA256='e' * 64))
    for number in (2, 3):
        files[p + 'transport-%06d.json' % number] = enc(dict(argv=query, binding=binding, inputSHA256='e' * 64))
    baseline = enc(dict(nft=NFT, topology=TOPOLOGY, labnetFeatures=b64(b'rx: on\n'), uplinkFeatures=b64(b'tx: on\n'),
                        services=SERVICES, guest={}, absence={}, git={}))
    files['host/admission/baseline.json'] = baseline
    files['host/admission/config.json'] = enc(dict(baseline=dict(sha256=sha(baseline)), admissionRoot=ADMISSION))
    state = dict(ownerTasks=['BimeronFull300Owner-%s=Running' % NONCE], taskState='Running',
                 dirsExist=['C:/BimeronFull300/%s=True' % NONCE, 'C:/BimeronStep10Probe/%s=False' % NONCE],
                 remoteListing=[dict(path='C:\\BimeronFull300\\%s\\transport\\config.json' % NONCE)],
                 processes=[dict(pid=3672, name='powershell.exe', parent=1224,
                                 cmd='powershell.exe -File "C:/BimeronFull300/%s/owner-supervisor.ps1" -Nonce %s' % (NONCE, NONCE))])
    if mutate:
        mutate(files, state)
    files['guest/guest-state.json'] = enc(state)
    files.update(extra or {})
    for name in drop:
        del files[name]
    entries = []
    for relative, raw in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        entries.append(dict(path=relative, size=len(raw), sha256=sha(raw)))
    (root / 'MANIFEST.json').write_bytes(enc(dict(schema='evidence-manifest-v1', run=NONCE, files=entries)))
    for relative, raw in files.items():
        if relative.startswith(p):
            target = private / relative[len(p):]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
    return private, query


class UnreservedFake(Fake):
    def __init__(self, private, tree=TREEF):
        super().__init__(private)
        self.once_sha = sha((private / 'owner-transport/proofs/supervisor-once.json').read_bytes())
        running = dict(tasks=[dict(state=4, instances=[INSTANCEF])],
                       processes=[dict(pid=3672, name='powershell.exe',
                                       commandLine='-File C:/BimeronFull300/' + NONCE + '/owner-supervisor.ps1')])
        self.states = [guest_state(**running), guest_state(**DONE),
                       guest_state(**dict(DONE, rootExists=False, probeExists=False))]
        self.identities = {pid: dict(pid=pid, creationFileTime=int(exact) if exact else tool.filetime(created) + 3,
                                     image=PYTHON if name == 'python.exe' else PS, parent=parent)
                           for pid, name, parent, created, exact, marker in tree if marker not in (None, 'conhost.exe 0x4')}

    def deliver(self, path):
        code, response, err = super().deliver(path)
        if json.loads(path.read_bytes())['op'] == 'exit-supervisor':
            instance = (path.parent.parent / 'task-final.json')
            instance.write_bytes(enc(dict(state=3, instanceGuids=[], lastTaskResult=0, instanceGuid=INSTANCEF)))
        return code, response, err

    def private_listing(self, names):
        self.calls.append(('private-listing',))
        return {n: sorted(os.listdir(self.private / n)) if (self.private / n).exists() else None for n in names}


class UnreservedSealTests(unittest.TestCase):
    def setUp(self):
        self.root = TEMP / ('dhu-' + uuid.uuid4().hex[:8])
        self.root.mkdir(parents=True)
        self.evidence = self.root / 'evidence'
        self.work = self.root / 'work'
        self.work.mkdir()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def make(self, **kwargs):
        shutil.rmtree(self.evidence, ignore_errors=True)
        self.private, self.query = build_unreserved_evidence(self.evidence, **kwargs)
        self.plan = tool.validate(tool.Evidence(self.evidence))
        self.fake = UnreservedFake(self.private)
        self.disposition = tool.Disposition(self.plan, self.fake, tool.Journal(self.work, NONCE))
        return self.plan

    def effects(self, kind):
        return [c for c in self.fake.calls if c[0] == kind]

    def test_f895_shaped_dry_run_plan(self):
        import contextlib, io
        plan = self.make()
        self.assertEqual(plan['modes'], dict(B1='act', B2='act', B3='act', B4='act'))
        self.assertEqual([(p['role'], p['pid'], p['creationFileTime']) for p in plan['processes']],
                         [('watcher', 44692, 134383977395835656), ('resident', 11128, None),
                          ('owner', 66184, 134383977360417797)])
        transient = plan['transientMonitorQueries']
        self.assertEqual([(t['pid'], t['parent'], t['image']) for t in transient], [(18356, 66184, tool.SSH)])
        self.assertEqual(transient[0]['argvSHA256'], sha(tool.canonical_json(self.query)))
        config = (self.private / 'owner-transport/config.json').read_bytes()
        expected = enc(dict(schema='full300-owner-command-v1', nonce=NONCE, configSHA256=sha(config), seq=1,
                            op='seal-no-launch', body={}))
        self.assertEqual(plan['seal'], expected)
        summary = tool.summary(plan)
        self.assertEqual(summary['b1Variant'], 'unreserved-seal')
        self.assertEqual(summary['unreservedSeal']['sealSHA256'], sha(expected))
        self.assertEqual(summary['unreservedSeal']['supervisorPid'], 3672)
        self.assertIn('MailboxClient', summary['actions']['B1'])
        self.assertIn('transient monitor query 18356', summary['actions']['B4'])
        self.assertEqual(plan['planSHA256'], sha(tool.canonical_json(summary)))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(tool.main(['dry-run', '--evidence', str(self.evidence)]), 0)
        report = json.loads(out.getvalue())
        self.assertEqual((report['planSHA256'], report['b1Variant']), (plan['planSHA256'], 'unreserved-seal'))
        basis = {b['pid']: b['basis'] for b in report['identityBasis']}
        self.assertTrue(basis[11128].startswith('not in journal: PID + creation time'))
        self.assertTrue(basis[66184].startswith('journal creationFileTime 134383977360417797'))
        # The variant is covered by the plan digest.
        self.assertNotEqual(plan['planSHA256'], sha(tool.canonical_json(dict(summary, b1Variant='reserved-seal'))))

    def test_f895_shaped_full_run_delivers_owner_built_seal(self):
        self.make()
        for step in ('B1', 'B2', 'B3'):
            self.disposition.run(step)
        self.assertEqual([c[1] for c in self.effects('deliver')], ['00000001.json', '00000002.json'])
        self.assertEqual((self.work / 'owner-transport/commands/00000001.json').read_bytes(), self.plan['seal'])
        names = sorted(n.name for n in (self.work / 'journal').iterdir())
        command = json.loads((self.work / 'journal' / [n for n in names if n.endswith('-command-1.json')][0]).read_bytes())
        self.assertEqual((command['value']['sha256'], command['value']['bytes'].encode()),
                         (self.plan['sealSHA256'], self.plan['seal']))
        performed = json.loads((self.work / 'journal' / [n for n in names if n.endswith('-B1-performed.json')][0]).read_bytes())
        self.assertEqual(performed['value']['variant'], 'unreserved-seal')
        exit_command = json.loads((self.work / 'owner-transport/commands/00000002.json').read_bytes())
        self.assertEqual((exit_command['op'], exit_command['seq']), ('exit-supervisor', 2))
        # The transient monitor query outlived the owner: a verified descendant in the leftover scan.
        created = tool.filetime(TREEF[4][3]) + 3  # same microsecond as the planned tree row
        self.fake.scan_rows.append(dict(pid=18356, parent=66184, name='ssh.exe', image=tool.SSH, creationFileTime=created,
                                        commandLine=tool.subprocess.list2cmdline(self.query)))
        self.fake.identities[18356] = dict(pid=18356, creationFileTime=created, image=tool.SSH, parent=66184)
        self.disposition.run('B4')
        self.assertEqual([c[1] for c in self.effects('terminate')], [44692, 11128, 66184, 18356])
        note = [n for n in sorted(os.listdir(self.work / 'journal')) if n.endswith('-B4-transient-ssh-18356.json')]
        self.assertEqual(len(note), 1)
        value = json.loads((self.work / 'journal' / note[0]).read_bytes())['value']
        self.assertTrue(value['live'])
        self.assertIn('leftover scan', value['note'])
        final = json.loads((self.work / 'final-record.json').read_bytes())
        self.assertEqual(final['status'], 'DISPOSED')

    def test_unknown_owner_child_still_refused(self):
        for extra in (((81030, 'cmd.exe', 66184, '2026-11-06T00:17:56.0000000Z', None, 'cmd /c x'),),
                      ((81031, 'ssh.exe', 66184, '2026-11-06T00:17:56.0000000Z', None, 'ssh other ' + NONCE),)):
            with self.assertRaisesRegex(tool.Refusal, 'role unknown or ambiguous: 8103'):
                self.make(tree=TREEF + extra)

    def test_transient_query_needs_owner_monitor_record(self):
        drop = tuple('host/private-root/transport-%06d.json' % n for n in (2, 3))
        with self.assertRaisesRegex(tool.Refusal, 'No owner capture status query'):
            self.make(drop=drop)

    def test_transient_query_tied_by_creation_window(self):
        plan = self.make()
        self.assertIn('newer than every journaled owner query identity',
                      plan['transientMonitorQueries'][0]['createdBasis'])
        with self.assertRaisesRegex(tool.Refusal, 'needs the process tree time: 18356'):
            self.make(utc=None)
        # Created after the tree was collected, or too long before it.
        with self.assertRaisesRegex(tool.Refusal, 'outside the owner query window: 18356'):
            self.make(utc='2026-11-06T00:17:55.0000000Z')
        with self.assertRaisesRegex(tool.Refusal, 'outside the owner query window: 18356'):
            self.make(utc='2026-11-06T00:18:56.0000000Z')
        # Older than a journaled owner query identity: not the in-flight query.
        newer = enc(dict(pid=4242, creationFileTime=tool.filetime('2026-11-06T00:17:55.2000000Z'), image=tool.SSH))
        with self.assertRaisesRegex(tool.Refusal, 'outside the owner query window: 18356'):
            self.make(extra={'host/private-root/original-transport-000003/transport-001-original.identity.json': newer})
        # The exact journaled identity of one owner query.
        exact = enc(dict(pid=18356, creationFileTime=tool.filetime('2026-11-06T00:17:55.1294460Z'), image=tool.SSH))
        plan = self.make(utc=None, extra={
            'host/private-root/original-transport-000003/transport-001-original.identity.json': exact})
        self.assertTrue(plan['transientMonitorQueries'][0]['createdBasis'].startswith('journaled owner query identity'))

    def test_live_host_receipt_refused_before_delivery(self):
        self.make()
        (self.private / 'owner-transport/receipts').mkdir()
        (self.private / 'owner-transport/receipts/00000001.json').write_bytes(b'{}')
        with self.assertRaisesRegex(tool.Refusal, 'reserved command, response or receipt'):
            self.disposition.run('B1')
        self.assertEqual((self.effects('deliver'), self.effects('guest-state')), ([], []))

    def test_reserved_and_unreserved_ambiguity_refused(self):
        def mutate(files, state):
            path = 'host/private-root/guest-control/resident-request-%020d.json' % 3
            files[path] = enc(dict(sequence=3, mode='submit', operation='seal-no-launch',
                                   path='C:\\held\\owner-transport\\commands\\00000001.json', requestSHA256='e' * 64))
        with self.assertRaisesRegex(tool.Refusal, 'Reserved/unreserved seal ambiguity'):
            self.make(mutate=mutate)

    def test_nonempty_guest_commands_refused(self):
        def mutate(files, state):
            files['guest/BimeronFull300/' + NONCE + '/transport/commands/00000001.json'] = b'{}'
        with self.assertRaisesRegex(tool.Refusal, 'Guest mailbox not empty in evidence'):
            self.make(mutate=mutate)

        def listing(files, state):
            state['remoteListing'].append(dict(path='C:\\BimeronFull300\\%s\\transport\\responses\\00000001.json' % NONCE))
        with self.assertRaisesRegex(tool.Refusal, 'Guest listing shows delivered commands'):
            self.make(mutate=listing)
        self.make()
        self.fake.states[0] = dict(self.fake.states[0], commands=['00000001.json'])
        with self.assertRaisesRegex(tool.Refusal, 'Guest transport commands/responses not empty'):
            self.disposition.run('B1')
        self.assertEqual(self.effects('deliver'), [])

    def test_live_reserved_host_command_refused_before_delivery(self):
        self.make()
        (self.private / 'owner-transport/commands').mkdir()
        (self.private / 'owner-transport/commands/00000001.json').write_bytes(self.plan['seal'])
        with self.assertRaisesRegex(tool.Refusal, 'holds a reserved command'):
            self.disposition.run('B1')
        self.assertEqual((self.effects('deliver'), self.effects('guest-state')), ([], []))

    def test_supervisor_once_must_match_and_name_the_supervisor(self):
        guest = 'guest/BimeronFull300/' + NONCE + '/transport/proofs/supervisor-once.json'
        with self.assertRaisesRegex(tool.Refusal, 'supervisor-once.json differs'):
            self.make(extra={guest: b'{"other":1}'})

        def other(files, state):
            state['processes'][0]['pid'] = 4000
        with self.assertRaisesRegex(tool.Refusal, 'supervisor named by supervisor-once'):
            self.make(mutate=other)

    def test_seal_bytes_differing_from_plan_refused_before_delivery(self):
        self.make()
        self.plan['seal'] = self.plan['seal'].replace(b'"body":{}', b'"body":{} ')
        with self.assertRaisesRegex(tool.Refusal, 'Seal bytes differ from the approved plan'):
            self.disposition.run('B1')
        self.assertEqual(self.effects('deliver'), [])

    @unittest.skipUnless((REAL_EVIDENCE_F89 / 'MANIFEST.json').exists(), 'evidence copy absent')
    def test_dry_run_against_real_f8956ea0_evidence_copy(self):
        plan = tool.validate(tool.Evidence(REAL_EVIDENCE_F89))
        self.assertEqual([(p['role'], p['pid']) for p in plan['processes']],
                         [('watcher', 44692), ('resident', 11128), ('owner', 66184)])
        self.assertEqual([t['pid'] for t in plan['transientMonitorQueries']], [18356])
        self.assertEqual((plan['b1Variant'], plan['supervisorPid']), ('unreserved-seal', 3672))


if __name__ == '__main__':
    sys.path.insert(0, str(tool.DRIVER))
    unittest.main()
