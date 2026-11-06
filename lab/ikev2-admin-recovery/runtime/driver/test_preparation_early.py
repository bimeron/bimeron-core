"""Complete local cancellation -> Stage -> preparation release, no VM/network."""
import base64
import copy
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest
from cancellation import control
from persistent import FirstFailure
from protected_evidence import check_exact_drain, check_early_preparation_exit
from protected_stage import Stage
from protected_transport import Adapter, Hold, encode, freeze, sha, strict

HERE = pathlib.Path(__file__).resolve().parent
N = 'b' * 64
PS = pathlib.Path('C:/Windows')/'System32/WindowsPowerShell/v1.0/powershell.exe'


class EarlyPreparation(unittest.TestCase):
    def start_host(self, root, scenario='early'):
        here = root/'driver'; here.mkdir()
        for name in ('prepare-task.ps1','cancellation.ps1','file-sha256.ps1'):
            shutil.copyfile(HERE/name, here/name)
        # The admitted cp-<16 hex> private run root, bound by run-identity.json.
        from admin_recovery import private_root_name
        out = here/private_root_name(N); out.mkdir()
        freeze(out/'run-identity.json', encode(dict(schema='fresh-admin-run-identity-v1', nonce=N, rootName=out.name)))
        freeze(out/'preparation-source.ps1', (here/'prepare-task.ps1').read_bytes())
        # Bootstrap-staged historical inputs: inert fixtures, never a live checkout path.
        freeze(out/'prior-expected.json', json.dumps(dict(guids=[
            '%08x-0000-4000-8000-%012x' % (i, i) for i in range(1, 23)])).encode())
        freeze(out/'retained-action.json', b'{"inert":true}')
        command = [str(PS), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                   '-File', str(HERE/'test-preparation-early-harness.ps1'), '-Driver', str(here),
                   '-Output', str(out), '-Nonce', N, '-Scenario', scenario]
        with (root/'test.log').open('wb') as log:
            process = subprocess.Popen(command, stdout=log, stderr=log,
                                       env=__import__('windows_powershell').environment(PS))
        return here, out, command, process

    def wait_file(self, path, process, root):
        until = time.monotonic()+15
        while not path.exists() and process.poll() is None and time.monotonic() < until:
            time.sleep(.05)
        self.assertTrue(path.exists(), '\n'.join(p.read_text(errors='replace') for p in root.rglob('*error.txt')) + (root/'test.log').read_text(errors='replace'))

    def adapter(self, out):
        calls = []
        def rpc(mode, path):
            c = strict(path.read_bytes()); root = path.parent if mode == 'preflight' else path.parent.parent
            calls.append(c.get('op', mode))
            if mode == 'preflight':
                freeze(root/'task-instance.json', encode(dict(instanceGuid='offline-instance')))
                freeze(root/'task-registration.json', encode(dict(xml='task', sddl='acl', fileSddl='file-acl')))
                return encode(dict(schema='full300-supervisor-once-v1', nonce=N, configSHA256=sha(path.read_bytes()),
                    instanceId='offline-instance', pid=7, creationFileTime='123', principalSid=c['principalSid'], sessionId=2, elevated=True))
            refs=[]
            if c['op']=='seal-no-launch':
                proof=encode(dict(schema='full300-no-launch-v1',nonce=N,configSHA256=c['configSHA256'],
                    supervisorOnceSHA256=sha((root/'proofs/supervisor-once.json').read_bytes()),
                    sealCommandSHA256=sha(path.read_bytes()),launchAttempted=False,sealed=True))
                freeze(root/'proofs/no-launch.json',proof)
                refs.append(dict(name='no-launch.json',sha256=sha(proof),length=len(proof)))
            elif c['op']=='exit-supervisor':
                freeze(root/'task-final.json',encode(dict(xml='task',sddl='acl',fileSddl='file-acl',state=3,instanceGuids=[],instanceGuid='offline-instance')))
                freeze(root/'proofs/supervisor-exit-ready.json',encode(dict(nonce=N,
                    proofSHA256=c['body']['noLaunch']['sha256'],supervisorOnceSHA256=sha((root/'proofs/supervisor-once.json').read_bytes()))))
            else: self.fail('Forbidden native command: '+c['op'])
            return encode(dict(schema='full300-owner-response-v1',nonce=N,configSHA256=c['configSHA256'],seq=c['seq'],
                commandSHA256=sha(path.read_bytes()),outcome='accepted',state='SEALED_NO_LAUNCH',owner=None,refs=refs,error=None))
        def forbidden(*args,**kwargs):
            raise AssertionError('Hermetic test: guest helper/child forbidden: '+repr(args[:2]))
        a=Adapter(HERE,out,N,FirstFailure(),rpc=rpc,principal=lambda:'S-1-5-21-1-2-3-1001',runner=forbidden,owned_ps=forbidden,
                  collect=lambda _:dict(nonce=N,files={},journal=b'',ras='No connections',bfe=b'<wfpstate/>'),
                  # The candidate ships no native image; deployment bytes are an inert fixture.
                  owner_path=freeze(out/'nonexecutable-owner.fixture',b'NOT AN EXECUTABLE'))
        return a,calls

    @unittest.skipUnless(PS.exists(), 'Windows PowerShell offline harness')
    def test_complete_original_host_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory); here,out,command,process=self.start_host(root)
            a,calls=self.adapter(out);a.bind_preparation(process,command)
            a.failure.set('injected startup failure')
            stage=Stage(HERE,out,N,a.failure,adapter=a);stage.start();stage.thread.join(5)
            self.assertFalse(stage.thread.is_alive())
            self.wait_file(out/'preparation-early-proof.json',process,root)
            class Transport:
                def __init__(self, mode): self.mode=mode
                def poll(self): return 0
                def result(self):
                    stop=strict((out/'stop-request.json').read_bytes())
                    if self.mode=='stop': return dict(nonce=N,delivered=True,requestId=stop['requestId'],adoptedRequest=stop)
                    return dict(nonce=N,stopRequest=stop,readers={},inspectorFinal=None,task=dict(state=3,instances=0))
            self.assertTrue(control(process,lambda mode,*_:Transport(mode),out,N,a.failure,900,lambda _:None,
                                    readers=True,before_restore=stage.before_restore),
                            (out/'cancellation-evidence.json').read_text())
            a.verify_preparation_exit()
            self.assertEqual(process.returncode,1)  # Original cancellation stays a failure.
            self.assertEqual(calls,['preflight','seal-no-launch','exit-supervisor'])
            self.assertTrue(stage.restorationAllowed)
            self.assertEqual(check_exact_drain(a.early_drain,N)['status'],'PASS')
            self.assertEqual(strict((out/'preparation-host-exit.json').read_bytes())['exitCode'],1)
            result=strict((out/'protected-result.json').read_bytes())
            self.assertEqual(result['measurement']['status'],'INCONCLUSIVE')
            self.assertEqual(result['measurement']['reasons'],['CLOCK_BOUND_UNPROVEN'])
            self.assertEqual(result['lifecycle'],'RESTORATION_ALLOWED')
            self.assertFalse(result['observationCompleted']);self.assertTrue(result['executionFailure'])
            self.assertIsNone(result['cleanupFailure']);self.assertTrue(result['restorationAllowed'])
            self.assertEqual(strict((out/'protected-failure.json').read_bytes())['lifecycle'],'ABORTED')
            original=(out/'protected-result.json').read_bytes();stage.before_restore()
            self.assertEqual((out/'protected-result.json').read_bytes(),original)
            self.check_mutations(a.early_drain)
            released=dict(a.early_drain, release=(out/'preparation-release.json').read_bytes(),
                          cleanup=(out/'protected-cleanup.json').read_bytes(),
                          closed=(out/'preparation-session-closed.json').read_bytes())
            self.assertEqual(check_early_preparation_exit(released,N)['status'],'PASS')
            for key in ('release','cleanup','closed'):
                broken=dict(released);broken[key]=b'{}'
                self.assertNotEqual(check_early_preparation_exit(broken,N)['status'],'PASS')
            for key in ('host','sessionId','stateAfter','releaseSHA256'):
                closed=strict(released['closed']);closed[key]='changed'
                self.assertNotEqual(check_early_preparation_exit(dict(released,closed=encode(closed)),N)['status'],'PASS')

    def check_mutations(self, bundle):
        for field in ('deploymentAttempted','wrapperMutationAttempted','inspectorLaunchAttempted','sealed','inspectorJob','controlSession','sourceSHA256','host','stage','session'):
            with self.subTest(field=field):
                b=copy.deepcopy(bundle);p=strict(b['early'])
                p[field] = True if field.endswith('Attempted') else False if field=='sealed' else 'changed'
                b['early']=encode(p)
                self.assertNotEqual(check_exact_drain(b,N)['status'],'PASS')
        for field in ('admissions','closures','start','source'):
            with self.subTest(field=field):
                b=copy.deepcopy(bundle);b[field]=b'{}'
                self.assertNotEqual(check_exact_drain(b,N)['status'],'PASS')
        for field in ('wrapper','policy','task'):
            b=copy.deepcopy(bundle);p=strict(b['early']);current=strict(base64.b64decode(p['current']))
            current[field] = {'state':4} if field=='task' else base64.b64encode(b'changed').decode()
            p['current']=base64.b64encode(encode(current)).decode();b['early']=encode(p)
            self.assertNotEqual(check_exact_drain(b,N)['status'],'PASS')
        b=copy.deepcopy(bundle);b['files']['inspector-final.json']=b'{}'
        self.assertNotEqual(check_exact_drain(b,N)['status'],'PASS')

    @unittest.skipUnless(PS.exists(), 'Windows PowerShell offline harness')
    def test_deployment_intent_excludes_early_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);here,out,command,p=self.start_host(root,'deployed')
            self.assertEqual(p.wait(timeout=15),1)
            self.assertFalse((out/'preparation-early-proof.json').exists(),(root/'test.log').read_text(errors='replace'))
            self.assertFalse((out/'preparation-session-closed.json').exists())
            self.assertIn('Injected refusal after deployment intent', '\n'.join(p.read_text(errors='replace') for p in root.rglob('*error.txt')))

    @unittest.skipUnless(PS.exists(), 'Windows PowerShell offline harness')
    def test_no_permit_never_closes_session(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);here,out,command,p=self.start_host(root,'release-refused')
            self.assertEqual(p.wait(timeout=15),1)
            self.assertTrue((out/'preparation-early-proof.json').exists(),'\n'.join(p.read_text(errors='replace') for p in root.rglob('*error.txt'))+(root/'test.log').read_text(errors='replace'))
            self.assertFalse((out/'preparation-session-closed.json').exists())
            self.assertFalse(strict((out/'preparation-outcome.json').read_bytes())['restored'])

    @unittest.skipUnless(PS.exists(), 'Windows PowerShell offline harness')
    def test_corrupt_release_does_not_close_original_session(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);here,out,command,p=self.start_host(root,'release-refused')
            self.wait_file(out/'preparation-early-proof.json',p,root)
            from cancellation import publish_once
            publish_once(out/'protected-cleanup.json',dict(nonce=N,rasAbsent=True,ownerAbsent=True,taskReady=True))
            publish_once(out/'preparation-release.json',dict(schema='full300-preparation-release-v1',nonce=N,
                earlySHA256=sha((out/'preparation-early-proof.json').read_bytes()),cleanupSHA256='0'*64))
            publish_once(out/'restore-permit.json',dict(schema=1,nonce=N,readersDrained=True))
            self.assertEqual(p.wait(timeout=15),1)
            self.assertFalse((out/'preparation-session-closed.json').exists())
            self.assertFalse(strict((out/'preparation-outcome.json').read_bytes())['restored'])
            self.assertIn('explicit early release binding', '\n'.join(p.read_text(errors='replace') for p in root.rglob('*error.txt')))

    def test_native_attempt_cannot_take_early_branch(self):
        with tempfile.TemporaryDirectory() as directory:
            a,_=self.adapter(pathlib.Path(directory))
            from types import SimpleNamespace
            a.preparation_process=SimpleNamespace(poll=lambda:None)
            for pending,attempts in ((None,{'launch'}),(('uncertain',),set())):
                a.client=SimpleNamespace(attempted=attempts,pending=pending)
                with self.assertRaises(Hold):a._early_drain()
            a.client=None;a.binding={'Nonce':N}
            with self.assertRaises(Hold):a._early_drain()


if __name__=='__main__': unittest.main()
