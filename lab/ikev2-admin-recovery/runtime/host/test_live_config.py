"""Offline only: all subprocess boundaries are fake, including nft and PSDirect."""
import copy
import os
import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'driver'))
import live_prepare as lp
from protected_transport import Hold, encode, sha, strict


SSH = 'C:/Windows/System32/OpenSSH/ssh.exe'

class LiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.path = self.root/'live-config.json'
        self.binding = dict(SHA256=sha(b'offline-exe'), Nonce='b'*64, PolicySHA256='c'*64)
        self.nonce = self.binding['Nonce']
        self.owner = dict(pid=123, creationFileTime='123456789',
                          path='C:/BimeronFull300/'+self.nonce+'/full300-owner.exe',
                          sha256=self.binding['SHA256'], handleState='live', exitCode=None)
        self.table = 'ikeq_l'+self.nonce[:16]
        self.template = {'nftables': [{'table': {'family': 'netdev', 'name': 'ikeq_fixture'}}]}
        self.topology = dict(links=[], addresses=[], routes=[])
        self.fixture = dict(schema='l1-live-fixture-v1', vm=lp.VM, guest=lp.GUEST,
            principalSid='<LAB_GUEST_SID_1001>', guestIP='192.0.2.2',
            guestMAC='<LAB_GUEST_MAC>', peer='<LAB_PUBLIC_IP>', profile='Bimeron Step8',
            serverName='ikev2.bimeron.test', caSHA256=sha(b'offline-ca'), lab='labnet', uplink='uplink')
        self.blobs = dict(renderer=b"def render(run, lab, uplink):\n return 'table netdev ikeq_'+run+' {}\\n'\n",
            expected=encode(self.template), fixture=encode(self.fixture), ca=b'offline-ca',
            topology=encode(self.topology), events=b'{"offlineTest":"only"}\n', ownerExe=b'offline-exe',
            hostCode=encode(dict(schema='l1-host-code-v1', files={n:sha(p.read_bytes()) for n,p in lp.host_code_paths().items()})))
        self.blobs['kernel'] = encode(dict(schema='l1-kernel-result-v1', result='PASS',
            **{n+'SHA256':sha(self.blobs[n]) for n in ('renderer','expected','fixture','topology','events')},
            tests={n:'PASS' for n in ('valid500','valid4500','esp','udpESP','keepalive','truncated','markerOnly',
                'wrongVersion','wrongExchange','firstFragment','laterFragment','ipv6','dnsInput','existingFlow')}))
        self.blobs['review'] = encode(dict(schema='l1-review-v1', effort='HIGH', verdict='APPROVED',
            artifacts={n:sha(b) for n,b in self.blobs.items()}))
        self.config = dict(schema='l1-live-config-v1', templateTable='ikeq_fixture',
            artifacts={n:dict(path=n, sha256=sha(b)) for n,b in self.blobs.items()})
        self.write()
        self.calls=[]; self.installed=False; self.noop=False; self.changed=False
        self.env=patch.dict(os.environ, LOCALAPPDATA=str(self.root))
        self.env.start(); self.addCleanup(self.env.stop)

    def write(self):
        for n,b in self.blobs.items(): (self.root/n).write_bytes(b)
        self.path.write_bytes(encode(self.config))

    def fake_run(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[0] != SSH:
            proof = strict(pathlib.Path(args[-1]).read_bytes())
            return SimpleNamespace(returncode=0, stderr=b'offline stderr', stdout=encode(dict(nonce=self.nonce,
                sha256=sha(encode(proof['admission'])), name='live-admission.json')))
        command=args[-1]
        if command.startswith('ip -j '): raw=b'[]'
        elif command.startswith('sudo ethtool -k '): raw=b'Features:\ngeneric-receive-offload: off\n'
        elif command == 'sudo nft -j list ruleset':
            value={'nftables': []}
            if self.installed and not self.noop:
                value=lp.substitute(self.template, 'ikeq_fixture', self.table)
            if self.installed and self.changed:
                value['nftables'].append({'table':dict(family='ip', name='unrelated')})
            raw=encode(value)
        elif command == 'sudo nft -f -': self.installed=True; raw=b''
        elif command == 'sudo nft --check -f -': raw=b''
        else: raise AssertionError(command)
        return SimpleNamespace(returncode=0, stderr=b'offline stderr', stdout=raw)

    def prepare(self):
        return lp.prepare_live(self.binding, self.nonce, self.owner, ssh=SSH, out=self.root/'run', config_path=self.path, runner=self.fake_run)

    def test_success_and_fixed_commands(self):
        result=self.prepare()
        self.assertEqual(result['Binding'], self.binding)
        self.assertEqual(sum(a[0]!=SSH for a,_ in self.calls), 1)
        commands=[a[-1] for a,_ in self.calls if a[0]==SSH]
        self.assertEqual(commands[-2:], ['sudo nft -f -','sudo nft -j list ruleset'])
        for args, kw in self.calls:
            self.assertNotIn('shell',kw)
            if args[0]==SSH:
                self.assertIn('StrictHostKeyChecking=yes',args)
                self.assertIn('HostKeyAlias=step8-observer',args)
                self.assertIn('BatchMode=yes',args)
        batch=[kw['input'] for a,kw in self.calls if a[-1]=='sudo nft -f -'][0]
        self.assertIn(self.table.encode(), batch)
        for name in ('before.raw.json','after.raw.json','before.json','after.json','readback.json','verified.json','publication.json'):
            self.assertTrue((self.root/'run/live'/name).is_file())
        with self.assertRaises(FileExistsError): self.prepare()

    def test_noop_installer_never_publishes(self):
        self.noop=True
        with self.assertRaises(Hold): self.prepare()
        self.assertTrue(all(a[0]==SSH for a,_ in self.calls))

    def test_unrelated_change_never_publishes(self):
        self.changed=True
        with self.assertRaises(Hold): self.prepare()
        self.assertTrue(all(a[0]==SSH for a,_ in self.calls))

    def test_all_artifact_hashes_recomputed(self):
        for name in self.blobs:
            with self.subTest(name=name):
                (self.root/name).write_bytes(self.blobs[name]+b' ')
                with self.assertRaises(Hold): lp.load_config(self.path)
                (self.root/name).write_bytes(self.blobs[name])

    def test_missing_kernel_refuses_before_command(self):
        (self.root/'kernel').unlink()
        with self.assertRaises(FileNotFoundError): self.prepare()
        self.assertEqual(self.calls, [])

    def test_wrong_reviewed_executable_refuses_before_command(self):
        self.binding['SHA256']='e'*64; self.owner['sha256']='e'*64
        with self.assertRaisesRegex(Hold,'Reviewed executable'): self.prepare()
        self.assertEqual(self.calls, [])

    def test_installer_error_or_timeout_never_publishes(self):
        import subprocess
        original=self.fake_run
        def failed(args, **kw):
            if args[-1]=='sudo nft -f -':
                original(args, **kw)
                raise subprocess.TimeoutExpired(args,15)
            return original(args, **kw)
        self.fake_run=failed
        with self.assertRaises(subprocess.TimeoutExpired): self.prepare()
        self.assertTrue(self.installed)
        self.assertTrue(all(a[0]==SSH for a,_ in self.calls))
        count=len(self.calls)
        with self.assertRaises(FileExistsError): self.prepare()
        self.assertEqual(len(self.calls),count)

    def test_publisher_failure_is_not_retried(self):
        original=self.fake_run
        def failed(args, **kw):
            r=original(args, **kw)
            if args[0]!=SSH: r.returncode=1
            return r
        self.fake_run=failed
        with self.assertRaisesRegex(Hold,'publication uncertain'): self.prepare()
        evidence=self.root/'run/live'
        self.assertEqual((evidence/'publisher.stderr').read_bytes(), b'offline stderr')
        self.assertTrue((evidence/'publisher.stdout').read_bytes())
        self.assertEqual(strict((evidence/'publisher-result.json').read_bytes()), dict(returncode=1))
        with self.assertRaises(Hold): lp.freeze(evidence/'publisher.stderr', b'replacement')
        self.assertEqual(sum(a[0]!=SSH for a,_ in self.calls),1)
        with self.assertRaises(FileExistsError): self.prepare()

    def test_config_bool_unknown_duplicate_refused(self):
        self.path.write_bytes(b'{"schema":1,"schema":2}')
        with self.assertRaises(Hold): lp.load_config(self.path)
        for field,value in [('schema', True),('enabled',True)]:
            bad=dict(self.config);bad[field]=value;self.path.write_bytes(encode(bad))
            with self.assertRaises(Hold): lp.load_config(self.path)

    def test_owner_live_and_current_binding(self):
        for key,value in [('pid',True),('handleState','signalled'),('exitCode',0),('sha256','d'*64),('path','C:/other.exe')]:
            owner=dict(self.owner);owner[key]=value
            with self.subTest(key=key), self.assertRaises(Hold): lp.validate_binding(self.binding,self.nonce,owner)
        with self.assertRaises(Hold): lp.validate_binding(self.binding,'d'*64,self.owner)

    def test_topology_only_lease_countdowns_ignored(self):
        before=dict(links=[],routes=[],addresses=[dict(ifname='labnet',addr_info=[dict(local='192.0.2.1',valid_life_time=40,preferred_life_time=20)])])
        after=copy.deepcopy(before);after['addresses'][0]['addr_info'][0]['valid_life_time']=30
        self.assertEqual(lp.stable_topology(before),lp.stable_topology(after))
        after['addresses'][0]['addr_info'][0]['local']='192.0.2.9'
        self.assertNotEqual(lp.stable_topology(before),lp.stable_topology(after))

    def test_nft_only_documented_volatility_ignored(self):
        before={'nftables':[{'metainfo':{'version':'1'}},{'rule':{'handle':1,'expr':[{'counter':{'packets':1,'bytes':4}},{'accept':None}]}}]}
        after=copy.deepcopy(before);after['nftables'][1]['rule']['handle']=12
        after['nftables'][1]['rule']['expr'][0]['counter']['packets']=5
        self.assertEqual(lp.canonical(before),lp.canonical(after))
        after['nftables'][1]['rule']['expr'][1]={'drop':None}
        self.assertNotEqual(lp.canonical(before),lp.canonical(after))

    def test_failed_establishment_safe_restoration_is_not_pass(self):
        live=dict(Binding=self.binding,Attempted=True,NoDial=False,NativeEntered=True,NativeReturned=True,
                  ReturnedZero=True,LiveEstablished=False,CleanupSucceeded=True,EvidenceFailed=False,Errors=['dial error'])
        status=dict(self.binding,State='CLOSED',Live=live)
        self.assertEqual(lp.live_outcome(status,self.binding)['establishment'],'FAIL')
        live['CleanupSucceeded']=False
        with self.assertRaises(Hold): lp.live_outcome(status,self.binding)

    def test_reviewed_host_code_change_refuses(self):
        code=strict(self.blobs['hostCode']); code['files'][next(iter(code['files']))]='0'*64
        self.blobs['hostCode']=encode(code);self.config['artifacts']['hostCode']['sha256']=sha(self.blobs['hostCode']);self.write()
        with self.assertRaisesRegex(Hold,'host code changed'): lp.load_config(self.path)


if __name__=='__main__': unittest.main()
