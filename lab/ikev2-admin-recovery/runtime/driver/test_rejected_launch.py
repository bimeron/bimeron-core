"""Real offline Python mailbox -> persistent PowerShell supervisor regressions.

No VM, network, scheduler or native owner is invoked. External collection and
task/identity facts are fixtures; all recovery and evidence validators are real.
"""
import base64
import copy
import os
import pathlib
import queue
import subprocess
import tempfile
import threading
import unittest

from cancellation import freeze_controller_drain
from persistent import FirstFailure
from protected_stage import Stage
from protected_transport import Adapter, Hold, encode, freeze, sha, strict

HERE = pathlib.Path(__file__).resolve().parent
N = 'a' * 64


class Bridge:
    def __init__(self, root):
        self.root = root
        for name in ('commands', 'responses', 'proofs', 'samples'):
            (root / 'transport' / name).mkdir(parents=True, exist_ok=True)
        exe = pathlib.Path('C:/Windows') / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        if not exe.exists():
            raise RuntimeError('Windows PowerShell is required for this offline integration test')
        self.stderr = tempfile.TemporaryFile()
        self.process = subprocess.Popen([str(exe), '-NoProfile', '-NonInteractive',
            '-ExecutionPolicy', 'Bypass', '-File', str(HERE / 'test-rejected-launch-bridge.ps1'),
            '-Root', str(root)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, text=True, creationflags=subprocess.CREATE_NO_WINDOW,
            env=__import__('windows_powershell').environment(exe))
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.calls = []
        self.lose = False
        self.mismatch = False

    def _read(self):
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put('')

    def exchange(self, mode, **values):
        self.process.stdin.write(encode(dict(mode=mode, **values)).decode() + '\n')
        self.process.stdin.flush()
        try:
            line = self.lines.get(timeout=20)
        except queue.Empty:
            raise AssertionError('Offline bridge exceeded 20-second deadline') from None
        if not line:
            self.stderr.seek(0)
            raise AssertionError('Bridge exited: ' + self.stderr.read().decode(errors='replace'))
        result = strict(line)
        if not result['ok']:
            raise AssertionError('Bridge failed: ' + result['error'])
        return result

    def __call__(self, mode, path):
        value = strict(path.read_bytes())
        self.calls.append((mode, value.get('op', 'preflight')))
        host = path.parent if mode == 'preflight' else path.parent.parent
        if mode == 'preflight':
            for source in (host / 'deployment').iterdir():
                freeze(self.root / source.name, source.read_bytes())
            freeze(self.root / 'deployment.json', (host / 'deployment.json').read_bytes())
            freeze(self.root / 'transport/config.json', path.read_bytes())
            registration = encode(dict(xml='offline-task', sddl='offline-acl', fileSddl='offline-file-acl'))
            freeze(self.root / 'transport/task-registration.json', registration)
            freeze(host / 'task-registration.json', registration)
            freeze(host / 'task-instance.json', encode(dict(instanceGuid='offline-instance')))
        elif mode == 'submit':
            for source in (host / 'proofs').iterdir():
                freeze(self.root / 'transport/proofs' / source.name, source.read_bytes())
            freeze(self.root / 'transport/commands' / path.name, path.read_bytes())
        result = self.exchange(mode, seq=value.get('seq'))
        raw = base64.b64decode(result['raw'])
        for folder in ('proofs', 'samples'):
            for source in (self.root / 'transport' / folder).iterdir():
                freeze(host / folder / source.name, source.read_bytes())
        if value.get('op') == 'exit-supervisor':
            freeze(host / 'task-final.json', encode(dict(xml='offline-task', sddl='offline-acl', fileSddl='offline-file-acl',
                state=3, instanceGuids=[], instanceGuid='offline-instance')))
        if self.lose:
            raise TimeoutError('Injected lost response after real supervisor dispatch')
        if self.mismatch:
            response = strict(raw)
            response['commandSHA256'] = '0' * 64
            return encode(response)
        return raw

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()  # Only this test's retained bridge, never a native owner.
            self.process.wait(timeout=5)
        self.reader.join(5)
        self.process.stdout.close()
        self.stderr.close()


def forbidden_runner(*args, **kwargs):
    raise AssertionError('Hermetic test: no local child process may reach a guest: ' + repr(args[:1]))


class OfflineHelpers:
    """Replaces every Adapter._ps helper; never runs protected-guest.ps1/guest-read.ps1."""
    def __init__(self, nonce):
        self.nonce, self.calls = nonce, []

    def __call__(self, script, args, timeout):
        values = dict(zip(args[::2], args[1::2]))
        self.calls.append((script, values.get('-Operation')))
        if (script != 'protected-guest.ps1' or values.get('-Operation') != 'transition'
                or values.get('-Nonce') != self.nonce):
            raise AssertionError('Hermetic test: forbidden guest helper ' + script + ' ' + repr(args))
        raw = pathlib.Path(values['-RequestPath']).read_bytes()
        return encode(dict(nonce=self.nonce, sha256=sha(raw), name='transition.json'))


class RejectedLaunchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = pathlib.Path(self.temp.name) / 'host'
        self.out.mkdir()
        self.bridge = Bridge(pathlib.Path(self.temp.name) / 'guest')
        self.addCleanup(self.bridge.close)
        owner = freeze(self.out / 'nonexecutable-owner.fixture', b'NOT AN EXECUTABLE')
        files = {'expected.json': encode(dict(registration={'xml': 'original'})),
                 'registration.json': encode({'xml': 'original'}),
                 'inspector-final.json': encode(dict(nonce=N, launchNeverOccurred=True, launch=None, processes=[]))}
        files['inspector-exit-proof.json'] = encode(dict(nonce=N, waitResult='signalled',
            inspectorFinalSHA256=sha(files['inspector-final.json']), expectedSHA256=sha(files['expected.json'])))
        collected = dict(nonce=N, files=files, journal=b'', pcap=b'',
            task=dict(nonce=N, state=3, instanceGuids=[]), ras='No connections', bfe=b'<wfpstate/>')
        self.a = Adapter(HERE, self.out, N, FirstFailure(), rpc=self.bridge,
            collect=lambda _: copy.deepcopy(collected), principal=lambda: 'S-1-5-21-1-2-3-1001', owner_path=owner,
            runner=forbidden_runner, owned_ps=OfflineHelpers(N))
        self.a.preflight(N)
        # Correct envelope/references and real bytes, deliberately invalid admission
        # schema: Assert-OwnerLaunchBinding must refuse before launchAttempted.
        p = self.a.client.proof
        self.a.launch_body = dict(admission=p('admission.json', b'{}'),
            producerPins=p('producer-pins.json', b'[]'), admissionEvidence=p('admission-evidence.json', b'{}'))

    def assert_no_native(self):
        state = self.bridge.exchange('inspect')
        self.assertEqual(state['startCalls'], 0)
        self.assertFalse((self.bridge.root / 'transport/launch-intent.json').exists())
        self.assertFalse((self.bridge.root / 'cleanup-request.json').exists())
        self.assertNotIn(('submit', 'cleanup'), self.bridge.calls)

    def reject(self):
        with self.assertRaisesRegex(Hold, 'Supervisor refusal: Unexpected field count'):
            self.a.launch()
        response = self.a.client.responses['launch']
        self.assertEqual((response['outcome'], response['state'], response['owner']), ('rejected', 'READY', None))

    def test_original_seal_and_real_stage_no_native_restore(self):
        self.reject()
        freeze_controller_drain(self.out, N, {}, {})
        stage = Stage(HERE, self.out, N, self.a.failure, adapter=self.a)
        # Resume at the actual before_restore entry after the failed launch.
        stage.thread = threading.Thread(target=lambda: None)
        stage.thread.start(); stage.thread.join()
        stage.ownerMayExist = True
        stage.executionFailure = Hold('Admission rejected')
        stage.before_restore()
        self.assertTrue(stage.restorationAllowed)
        self.assertFalse(stage.ownerMayExist)
        self.assertIsNone(stage.binding)
        self.assertFalse(stage.cleanupAttempted)
        proof = strict((self.a.root / 'proofs/no-launch.json').read_bytes())
        self.assertEqual(proof['supervisorOnceSHA256'], sha((self.a.root / 'proofs/supervisor-once.json').read_bytes()))
        self.assertEqual(proof['supervisorOnceSHA256'], self.bridge.exchange('inspect')['once'])
        self.assertEqual(self.bridge.calls, [('preflight', 'preflight'), ('submit', 'launch'),
            ('submit', 'seal-no-launch'), ('submit', 'exit-supervisor')])
        stage.before_restore()
        with self.assertRaises(Hold): self.a.launch()
        self.assert_no_native()

    def test_lost_response_reconciles_fetch_only(self):
        self.bridge.lose = True
        with self.assertRaises(TimeoutError): self.a.launch()
        with self.assertRaises(Hold): self.a.launch()
        self.bridge.lose = False
        self.assertIsNone(self.a.recover_binding())
        self.assertEqual(self.bridge.calls[1:], [('submit', 'launch'), ('fetch', 'launch'), ('submit', 'seal-no-launch')])
        self.assert_no_native()

    def test_uncertain_launch_cannot_seal(self):
        self.bridge.lose = True
        with self.assertRaises(TimeoutError): self.a.launch()
        stage = Stage(HERE, self.out, N, self.a.failure, adapter=self.a)
        stage.thread = threading.Thread(target=lambda: None)
        stage.thread.start(); stage.thread.join()
        stage.ownerMayExist = True
        with self.assertRaises(TimeoutError): stage.before_restore()
        self.assertEqual(stage.lifecycle, 'HOLD')
        self.assertTrue(stage.ownerMayExist)
        self.assertFalse(stage.restorationAllowed)
        self.assertFalse(stage.cleanupAttempted)
        self.assertFalse((self.out / 'protected-cleanup.json').exists())
        self.assertIsNotNone(self.a.client.pending)
        self.assertFalse(self.a.client.sealed)
        self.assertNotIn(('submit', 'seal-no-launch'), self.bridge.calls)
        self.assert_no_native()

    def test_hold_launch_response_does_not_authorize_recovery_seal(self):
        self.bridge.exchange('fault', state='HOLD', launchAttempted=True)
        with self.assertRaisesRegex(Hold, 'Launch forbidden'): self.a.launch()
        self.assertEqual(self.a.client.responses['launch']['outcome'], 'hold')
        with self.assertRaisesRegex(Hold, 'Original owner identity missing'):
            self.a.recover_binding()
        self.assertNotIn(('submit', 'seal-no-launch'), self.bridge.calls)
        self.assertFalse(self.a.client.sealed)
        self.assert_no_native()

    def test_mismatched_response_stays_pending(self):
        self.bridge.mismatch = True
        with self.assertRaisesRegex(Hold, 'Response binding mismatch'): self.a.launch()
        with self.assertRaisesRegex(Hold, 'Response binding mismatch'): self.a.recover_binding()
        self.assertNotIn('launch', self.a.client.responses)
        self.assertIsNotNone(self.a.client.pending)
        self.assertNotIn(('submit', 'seal-no-launch'), self.bridge.calls)
        self.assert_no_native()

    def test_hold_refuses_seal(self):
        self.bridge.exchange('fault', state='HOLD', launchAttempted=False)
        with self.assertRaisesRegex(Hold, 'Seal forbidden'): self.a._seal_no_launch()
        self.assertFalse((self.a.root / 'proofs/no-launch.json').exists())
        self.assert_no_native()

    def test_launch_attempted_refuses_seal(self):
        self.bridge.exchange('fault', state='READY', launchAttempted=True)
        with self.assertRaisesRegex(Hold, 'Seal forbidden'): self.a._seal_no_launch()
        self.assertEqual(self.a.client.responses['seal-no-launch']['outcome'], 'hold')
        self.assertFalse((self.a.root / 'proofs/no-launch.json').exists())
        self.assert_no_native()

    def test_tampered_seal_refused_without_second_command(self):
        self.reject()
        self.assertIsNone(self.a.recover_binding())
        path = self.a.root / 'proofs/no-launch.json'
        original = path.read_bytes()
        proof = strict(original)
        for key, value in [('supervisorOnceSHA256', '0' * 64), ('sealCommandSHA256', '0' * 64),
                           ('launchAttempted', True), ('sealed', False), ('nonce', 'b' * 64)]:
            with self.subTest(key=key):
                path.write_bytes(encode(dict(proof, **{key: value})))
                with self.assertRaisesRegex(Hold, 'seal unproven'): self.a.recover_binding()
        path.write_bytes(original)
        self.assertEqual(self.bridge.calls.count(('submit', 'seal-no-launch')), 1)
        self.assert_no_native()


if __name__ == '__main__':
    unittest.main()
