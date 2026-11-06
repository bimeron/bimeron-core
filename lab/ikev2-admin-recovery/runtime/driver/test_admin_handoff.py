"""Actual Handoff/Stage/Owner/ResidentRPC path, with inert process/remote seams."""
import base64
import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
from test_admin_recovery import fixture,request,Pins
import admin_recovery as a
import admin_evidence as e
import admin_watcher_endpoint
import protected_evidence
from protected_stage import Stage
from persistent import FirstFailure
from resident_rpc import ResidentRPC
from admin_processes import OriginalProcesses
from admin_transport import OriginalTransports
from admin_handoff import Handoff, read_checkout


def make_checkout(root,repo,git,packed=False):
    common=root/'common';gitdir=common/'worktrees'/'w';gitdir.mkdir(parents=True)
    NL='\n'
    (repo/'.git').write_bytes(('gitdir: '+gitdir.as_posix()+NL).encode())
    (gitdir/'gitdir').write_bytes(((repo/'.git').as_posix()+NL).encode())
    (gitdir/'commondir').write_bytes(('../..'+NL).encode())
    (gitdir/'HEAD').write_bytes(('ref: refs/heads/'+git['branch']+NL).encode())
    if packed:
        (common/'packed-refs').write_bytes(('# pack-refs with: peeled fully-peeled sorted'+NL+
            'b'*40+' refs/heads/other'+NL+git['HEAD']+' refs/heads/'+git['branch']+NL).encode())
    else:
        ref=common.joinpath('refs','heads',*git['branch'].split('/'));ref.parent.mkdir(parents=True)
        ref.write_bytes((git['HEAD']+NL).encode())
    return dict(gitDir=str(gitdir),commonDir=str(common))


class Tests(unittest.TestCase):
    GIT=dict(HEAD='a'*40,branch='feature/inert')

    def test_checkout_metadata_loose_and_packed(self):
        for packed in (False,True):
            with tempfile.TemporaryDirectory() as directory:
                root=pathlib.Path(directory);repo=root/'repo';repo.mkdir()
                checkout=make_checkout(root,repo,self.GIT,packed);records=[]
                value=read_checkout(Pins(),repo,checkout,self.GIT,records)
                self.assertEqual(value,dict(checkout,ref='packed' if packed else 'loose'))
                self.assertEqual(len(records),5)

    def test_checkout_metadata_refusals(self):
        NL='\n'
        def gitdir(c):return pathlib.Path(c['gitDir'])
        def common(c):return pathlib.Path(c['commonDir'])
        cases=[
            lambda r,c:(r/'.git').write_bytes(b'gitdir: C:/elsewhere/.git/worktrees/w\n'),
            lambda r,c:(r/'.git').write_bytes(('gitdir: '+gitdir(c).as_posix()+'\r\n').encode()),
            lambda r,c:(r/'.git').write_bytes(('gitdir: '+gitdir(c).as_posix()+NL+'x'+NL).encode()),
            lambda r,c:(gitdir(c)/'gitdir').write_bytes(b'C:/elsewhere/.git\n'),
            lambda r,c:(gitdir(c)/'commondir').write_bytes(b'../../..\n'),
            lambda r,c:(gitdir(c)/'HEAD').write_bytes(('a'*40+NL).encode()),
            lambda r,c:(gitdir(c)/'HEAD').write_bytes(b'ref: refs/heads/other\n'),
            lambda r,c:common(c).joinpath('refs','heads','feature','inert').write_bytes(('b'*40+NL).encode()),
            lambda r,c:(r/'.git').unlink(),
        ]
        for index,mutate in enumerate(cases):
            with self.subTest(index=index),tempfile.TemporaryDirectory() as directory:
                root=pathlib.Path(directory);repo=root/'repo';repo.mkdir()
                checkout=make_checkout(root,repo,self.GIT);mutate(repo,checkout)
                with self.assertRaises((a.Hold,OSError)):read_checkout(Pins(),repo,checkout,self.GIT,[])
        # Packed-refs: wrong commit, duplicate entry; configured paths must match.
        for text in ('b'*40+' refs/heads/feature/inert\n',
                     'a'*40+' refs/heads/feature/inert\n'+'a'*40+' refs/heads/feature/inert\n'):
            with tempfile.TemporaryDirectory() as directory:
                root=pathlib.Path(directory);repo=root/'repo';repo.mkdir()
                checkout=make_checkout(root,repo,self.GIT,True)
                (pathlib.Path(checkout['commonDir'])/'packed-refs').write_bytes(text.encode())
                with self.assertRaises(a.Hold):read_checkout(Pins(),repo,checkout,self.GIT,[])
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);repo=root/'repo';repo.mkdir()
            checkout=make_checkout(root,repo,self.GIT)
            for wrong in (dict(checkout,commonDir=str(root)),dict(checkout,gitDir=str(root))):
                with self.assertRaises((a.Hold,OSError)):read_checkout(Pins(),repo,wrong,self.GIT,[])
            for branch in ('../x','x.lock','-x','a//b'):
                with self.assertRaises(a.Hold):read_checkout(Pins(),repo,checkout,dict(self.GIT,branch=branch),[])

    def test_handoff_never_runs_git(self):
        import inspect,admin_handoff,admin_entry
        for module in (admin_handoff,admin_entry):
            source=inspect.getsource(module)
            self.assertNotIn('gitExecutable',source);self.assertNotIn("config['git']",source)
        self.assertIn("'gitCheckout'",inspect.getsource(admin_entry.run))

    def test_complete_original_path_waits_for_watcher_and_never_replays(self):
        self.complete_path(False)

    def test_precontroller_identity_failure_keeps_same_child_and_finishes(self):
        self.complete_path(True)

    def complete_path(self,precontroller):
        bound,r,old1,old2=fixture()
        old1=e.unpack(a.decode(old1));old2=e.unpack(a.decode(old2))
        value=lambda raw:e.unpack(a.decode(raw))['value']
        drain=value(old1['drain']);absence=value(old1['absence']);capture=value(old2['capture']);sink=value(old2['sink'])
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);repo=root/'inert-repo';repo.mkdir()
            base=e.unpack(a.decode(r['baseline']))
            for name in base['git']['files']:
                path=repo/name;path.parent.mkdir(exist_ok=True);path.write_bytes(name.encode())
                base['git']['files'][name]=a.sha(path.read_bytes())
            baseline=a.encode(e.pack(base));bound['baselineSHA256']=a.sha(baseline)
            checkout=make_checkout(root,repo,base['git'])
            r.update(baseline=baseline,baselineRoot=repo,operations={},operationOwners={},observations={},
                     gitCheckout=checkout)
            class Admission(Pins):
                def create_root(self,path):path.mkdir();return path
            class Journal(a.Journal):
                fail_phase1=True
                def write(self,name,raw):
                    if name=='administrative-phase1.json' and self.fail_phase1:
                        self.fail_phase1=False
                        raise OSError('inert phase1 publication failure after session closure')
                    return super().write(name,raw)
            owner=a.Owner(bound,Journal(root,Admission()),r,e.validate_phase1,e.validate_phase2)
            owner.fail(RuntimeError('original preparation failure'))
            process=SimpleNamespace(pid=21,poll=lambda:0)
            attempts=[];spawns=[]
            def handles(p):
                attempts.append(p)
                if precontroller and len(attempts)==1:raise OSError('inert identity read failure')
                return SimpleNamespace(creation=125,exe=sys.executable)
            def spawn_preparation(*args,**kwargs):
                spawns.append(args);return process
            processes=OriginalProcesses(owner,popen=spawn_preparation,identity=handles,
                                        environment=lambda path:{'PSModulePath':'INERT'})
            if precontroller:
                with self.assertRaises(OSError):processes('preparation',['inert-powershell'])
            else:processes('preparation',['inert-powershell'])
            r['spawn_owned']=processes
            (root/'preparation-session-closed.json').write_bytes(a.encode(dict(
                schema='fresh-preparation-sessions-closed-v1',nonce=bound['nonce'],
                host=dict(pid=21,creationFileTime='125'),sessions=[dict(instanceId='original',state='Closed')])))
            (root/'preparation-outcome.json').write_bytes(a.encode(dict(
                nonce=bound['nonce'],launchNeverOccurred=True,restored=True)))
            r['cancellation_state']=dict(process=process,owners={},pending={},completed=[],local={},
                request=None,status={},nonce=bound['nonce'],out=root)
            if precontroller:
                del r['cancellation_state']
                r['controllerEntered']=False
            failure=FirstFailure();failure.set('original failure')
            adapter=SimpleNamespace(verify_drain=lambda nonce:drain,final=lambda binding:absence,
                                     verify_preparation_exit=lambda:None,
                                     bind_preparation=lambda child,argv:self.assertIs(child,process))
            stage=Stage(root,root,bound['nonce'],failure,adapter,protected_evidence)
            stage.thread=SimpleNamespace(join=lambda **kwargs:None,is_alive=lambda:False)
            r.update(stage=stage,stop=SimpleNamespace(set=lambda:None),
                     thread=SimpleNamespace(join=lambda **kwargs:None,is_alive=lambda:False))
            resident_exit=[None];resident_effects=[]
            resident_process=SimpleNamespace(pid=22,poll=lambda:resident_exit[0])
            def spawn(*args,**kwargs):
                (root/'guest-control/resident-ready.json').write_bytes(a.encode(dict(
                    schema='fresh-resident-ready-v1',nonce=bound['nonce'],configSHA256=bound['configSHA256'])))
                return resident_process
            class Resident(ResidentRPC):
                def _publish(self,name,raw):
                    fresh=not (self.root/name).exists()
                    super()._publish(name,raw)
                    if not fresh:return
                    data=a.decode(raw)
                    if name.startswith('resident-request-'):
                        op=data['operation'];resident_effects.append(op)
                        output=(dict(nonce=bound['nonce'],scope='Process',value='Undefined',restored=True)
                                if op=='restore-session-policy' else base[op])
                        response=dict(schema='fresh-resident-response-v1',nonce=bound['nonce'],
                            configSHA256=bound['configSHA256'],sequence=data['sequence'],
                            requestSHA256=data['requestSHA256'],state='Collected',error=None,
                            output=base64.b64encode(a.encode(output)).decode())
                        (self.root/('resident-response-%020d.json'%data['sequence'])).write_bytes(a.encode(response))
                    elif name=='resident-close-request.json':
                        resident_effects.append('close')
                        (self.root/'resident-closed.json').write_bytes(a.encode(dict(
                            schema='fresh-resident-closed-v1',nonce=bound['nonce'],configSHA256=bound['configSHA256'],
                            sessionState='Closed',pending=0,normalCleanupSucceeded=False)))
                    elif name=='resident-finish-request.json':
                        resident_effects.append('finish');resident_exit[0]=0
                        (self.root/'resident-finished.json').write_bytes(raw)
            Resident(owner,root,popen=spawn,identity=lambda p:SimpleNamespace(creation=125,exe=sys.executable),environment=lambda path:{'PSModulePath':'INERT'})
            commands=[];mutations=[];health_reads=[0];sink_reads=[0]
            class Remote:
                def __init__(self,path,*args,**kwargs):self.children=[]
                def observe(self,argv,*args,**kwargs):
                    commands.append(argv);mutations.append(kwargs['mutation'])
                    command=argv[-1]
                    if 'nft -j' in command:return a.encode(base['nft'])
                    if 'ethtool -k' in command:return base['labnetFeatures']
                    if command.startswith('ip '):return b'[]'
                    if 'systemctl list-units' in command:
                        sink_reads[0]+=1
                        return (('step10-prep-'+bound['nonce']+'.service loaded active running inert\n').encode()
                                if sink_reads[0]==1 else b'')
                    if command.endswith('/cleanup-confirmed.json'):
                        return a.encode(dict(Nonce=bound['nonce'],OwnedRASAbsent=True,WFPOwnerCleaned=True))
                    if command.endswith('/sink-exit.json'):return a.encode(sink['retirement'])
                    if command.endswith('/health.json'):
                        health_reads[0]+=1
                        return a.encode(dict(ExitCode=None) if health_reads[0]==1 else capture['health'])
                    for name,result in [('ingress.pcap',capture['pcap']),('capture.log',capture['log'].encode()),
                        ('health.json',a.encode(capture['health'])),('identity.json',a.encode(capture['identity']))]:
                        if command.endswith('/'+name):return result
                    return b'{}'
            r.update(original_remote_transport=OriginalTransports(owner,transport=Remote),
                     ssh=['inert-ssh'],capture='/inert/capture-supervisor.py')
            watcher_exit=[None];r['independent']=SimpleNamespace(poll=lambda:watcher_exit[0])
            handoff=Handoff(owner)
            result=a.decode(owner.request(request(bound,1,'advance')))
            self.assertEqual(result['result'].get('observation'),'unresolved',result)
            self.assertEqual(resident_exit[0],0)
            self.assertIsNone(handoff.phase1)
            result=a.decode(owner.request(request(bound,2,'advance')))
            self.assertEqual(result['result'].get('ready'),'phase1',result)
            self.assertEqual(stage.lifecycle,'RESTORATION_ALLOWED')
            owner.request(request(bound,3,'phase1',handoff.phase1),phase1=handoff.phase1)
            result=a.decode(owner.request(request(bound,4,'advance')))
            self.assertEqual(result['result']['observation'],'unresolved')
            self.assertIsNone(handoff.phase2)
            self.assertFalse((root/'administrative-watcher-request.json').exists())
            result=a.decode(owner.request(request(bound,5,'advance')))
            self.assertEqual(result['result']['observation'],'unresolved')
            identity=dict(pid=bound['containmentOwner']['pid'],startFiletime=int(bound['containmentOwner']['creationFileTime']),
                          exeSHA256=bound['containmentOwner']['imageSHA256'],nonce=bound['nonce'])
            self.assertTrue(admin_watcher_endpoint.tick(root,identity,None,{}))
            ack=a.decode((root/'administrative-watcher-closed.json').read_bytes())
            self.assertEqual(ack['failure'],owner.failure)
            watcher_exit[0]=1
            owner.request(request(bound,6,'advance'))
            self.assertIsNotNone(handoff.phase2)
            owner.request(request(bound,7,'settle',handoff.phase2),phase2=handoff.phase2)
            self.assertEqual(owner.state,'SETTLED')
            self.assertFalse(owner.settlement['normalCleanupSucceeded'])
            self.assertEqual(len(spawns),1)
            self.assertTrue(all(child is process for child in attempts))
            if precontroller:self.assertTrue(r['preControllerSealed'])
            self.assertEqual(resident_effects,['restore-session-policy','guest','services','absence','close','finish'])
            self.assertEqual(sum('capture-supervisor.py stop' in x[-1] for x in commands),1)
            self.assertEqual(sum('systemctl stop' in x[-1] for x in commands),1)
            self.assertEqual(sum(x[-1]=='sudo python3 -' for x in commands),1)
            # Only the three fixed retirement effects are mutations; every
            # nft/ethtool/ip/git/cat readback is a non-mutating fresh read.
            self.assertEqual(sum(mutations),3)
            # The phase1 publication failed after 'eight' was recorded; the retry
            # reuses that proof instead of re-reading naturally changing nft/ip bytes.
            self.assertEqual(sum('nft -j' in x[-1] for x in commands),1)
            self.assertEqual(sum(x[-1].startswith('ip -j') for x in commands),3)
            # No git process at all: HEAD/branch come from pinned checkout files.
            self.assertFalse(any('git' in part for x in commands for part in x))
            pins=a.decode((root/'readonly-core-pins.json').read_bytes())['sources']
            self.assertEqual([pathlib.Path(x['path']).name for x in pins[:5]],['.git','gitdir','commondir','HEAD','inert'])
            self.assertEqual(len(pins),25)


if __name__=='__main__':unittest.main(verbosity=2)
