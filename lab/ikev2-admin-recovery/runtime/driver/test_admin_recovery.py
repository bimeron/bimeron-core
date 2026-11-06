"""Inert original-owner and real pure-validator failure tests. No native calls."""
import copy
import os
import pathlib
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import admin_recovery as a
import admin_evidence as e
import admin_watcher as w
import admin_native as n
import protected_transport as rpc
import settlement as s
import cancellation
import protected_stage
import threading
import subprocess
import time
import sys
import admin_bootstrap as bootstrap
from resident_rpc import ResidentRPC
from preparation_entry import execute
from admin_transport import OriginalTransports
from admin_collect import collect_original
from admin_handoff import Handoff
from admin_containment import Containment
from watcher_query import Query
import sink_contract

# All generated test state belongs to the authorized ignored candidate tree.
_scratch=pathlib.Path(__file__).resolve().parents[2]/'test-temporary'
_scratch.mkdir(exist_ok=True)
tempfile.tempdir=str(_scratch)


class Pins:
    canonical=staticmethod(n.WindowsAdmission.canonical)
    def revalidate(self): pass
    def pin_source(self, path): pass
    def pin_readonly_source(self, path, expected, limit):
        raw=pathlib.Path(path).read_bytes()
        a.require(len(raw)<=limit and a.sha(raw)==expected,'Read-only source content hash')
        return raw,dict(path=str(path),sha256=expected,components=[])
    def pin_readonly_content(self, path, limit, check):
        raw=pathlib.Path(self.canonical(path)).read_bytes()
        a.require(len(raw)<=limit,'Read-only source bound');check(raw)
        return raw,dict(path=str(path),sha256=a.sha(raw),components=[])


CHECKOUT=dict(gitDir=r'C:\inert\.git\worktrees\w',commonDir=r'C:\inert\.git')


def admin_git(git,checkout=CHECKOUT):
    return dict(HEAD=git['HEAD'],branch=git['branch'],files=dict(git['files']),
                worktree=dict(gitDir=checkout['gitDir'],commonDir=checkout['commonDir'],ref='loose'))


SANDBOX='S-1-5-21-2618600564-2757726436-3430918538-1025'
UNRESOLVED='S-1-5-21-1111111111-2222222222-3333333333-4444'
PYTHON=r'C:\Users\QA\AppData\Local\Programs\Python\Python311\python.exe'


class FakeVolume:
    """Inert stand-in for the CreateFileW/GetFileInformationByHandle/ReadFile seam."""
    def __init__(self,leaf,data,acl):
        self.entries={};self.handles={};self.next=100;self.acl=acl;self.on_read=None
        self.leaf=leaf;self.entry(leaf,False,data)
    def entry(self,path,directory,data=b''):
        self.entries[path]=dict(id=len(self.entries)+1,attributes=0x10 if directory else 0x20,
                                links=1,data=data,acl=list(self.acl))
        return self.entries[path]
    def install(self,sid):
        obj=n.WindowsAdmission.__new__(n.WindowsAdmission)
        obj.sid=sid;obj.pins=[];obj.closed=False;obj.code_dirs=frozenset()
        def create(path,*args):
            item=self.entries.get(path) or self.entry(path,True)
            self.next+=1;self.handles[self.next]=dict(item);return self.next
        def info(handle,pointer):
            item=self.handles[handle];target=pointer._obj
            target.attributes=item['attributes'];target.links=item['links'];target.volume=7
            target.indexHigh=0;target.indexLow=item['id'];target.sizeHigh=0;target.sizeLow=len(item['data'])
            return True
        def case(handle,kind,pointer,size):pointer._obj.value=0;return True
        def read(handle,buffer,size,count,overlapped):
            if self.on_read:self.on_read()
            data=self.handles[handle]['data'][:size];n.c.memmove(buffer,data,len(data))
            count._obj.value=len(data);return True
        obj.k=SimpleNamespace(CreateFileW=create,GetFileInformationByHandle=info,
            GetFileInformationByHandleEx=case,ReadFile=read,CloseHandle=lambda handle:True)
        def acl(handle):
            item=self.handles[handle]
            return item.get('owner',sid),False,item['acl'],repr(item['acl']).encode()
        obj._acl=acl
        return obj


class Journal:
    def __init__(self):
        self.values = {}
        self.bad = None
        self.admission = Pins()
    def claim(self,raw):
        if 'owner-created.json' in self.values:raise a.Hold('Original owner exists')
        self.write('owner-created.json',raw)
    def write(self, name, raw):
        if self.bad == name: raise OSError('inert publication failure')
        if name in self.values and self.values[name] != raw: raise a.Hold('collision')
        self.values[name] = raw


def fixture():
    user = dict(pid=11, creationFileTime='123', imageSHA256='1'*64)
    watcher = dict(pid=12, creationFileTime='124', imageSHA256='2'*64)
    guest = dict(systemRoot='inert',testSid=s.SID,computer=s.COMPUTER,adminTemp='inert',
        utc='inert',testTemp='inert',queryExit=0,query='test console 2 Active 00:00',
        wrapperSHA256='d'*64,shells=[dict(sid=s.SID,pid=123,result=0,session=2)],
        task=dict(sddl='inert',state=3,xml='inert',instances=0,settings=a.encode(dict(ExecutionTimeLimit='PT3M')).decode()),
        policy=[dict(Scope=dict(value=k,Value=v),ExecutionPolicy=dict(value=5,Value='Undefined'))
                for k,v in [(4,'MachinePolicy'),(3,'UserPolicy'),(0,'Process'),(1,'CurrentUser'),(2,'LocalMachine')]])
    absent = dict(wrapper=guest['wrapperSHA256'],owners=[],shells=[],
        ras='No connections\nCommand completed successfully.\n',guest=s.COMPUTER,dedicatedTasks=[],
        task=dict(state=3,duration='PT3M',xml='inert',instances=0,sddl='inert'),console='inert',reference='inert')
    base = dict(nft=dict(nftables=[]),labnetFeatures=b'inert features',uplinkFeatures=b'inert features',
        topology=dict(links=[],addresses=[],routes=[]),services=s.SERVICES,guest=guest,absence=absent,
        git=dict(HEAD='a'*40,branch='inert',status='synthetic',files={f'inert/{i}':'e'*64 for i in range(20)}))
    baseline = a.encode(e.pack(base))
    bound = dict(nonce='a'*64,configSHA256='b'*64,candidateSHA256='c'*64,
                 baselineSHA256=a.sha(baseline),owner=user,containmentOwner=watcher)
    resources = dict(baseline=baseline,observations={},c1Binding=None,waiterIdentity=user,nativeLaunchAttempted=False,
        entryInventory=dict(guestAttempted=False,preparationAttempted=True,captureAttempted=True,sinkAttempted=True,monitorAttempted=True),
        originalRun=dict(supervisorAttempted=False,stockDeploymentAttempted=False,stockPermitAttempted=False),
        operations={'original-session':dict(identity={'id':'inert'},submission='Submitted')},
        captureIdentity=dict(pid=9,start='123',boot='inert',command='f'*64),gitCheckout=dict(CHECKOUT))
    count = [0]
    def observe(name, value):
        count[0] += 1
        identity = dict(id='original-'+name)
        raw = a.encode(dict(schema='fresh-admin-observation-v1',binding=bound,
            identity=identity,sequence=count[0],value=e.pack(value)))
        resources['observations'][name] = dict(identity=identity,sequence=count[0],sha256=a.sha(raw),collected=True)
        return raw
    nonce = bound['nonce']
    files = {'inspector-final.json':a.encode(dict(nonce=nonce,launchNeverOccurred=True,launch=None,processes=[])),
             'expected.json':a.encode(dict(registration={'xml':'inert'})),
             'registration.json':a.encode({'xml':'inert'})}
    files['inspector-exit-proof.json'] = a.encode(dict(nonce=nonce,waitResult='signalled',
        inspectorFinalSHA256=a.sha(files['inspector-final.json']),expectedSHA256=a.sha(files['expected.json'])))
    drain = dict(wrapper=a.encode(dict(schema='full300-prelaunch-drain-v1',nonce=nonce)),files=files,
        admissions=a.encode(dict(nonce=nonce,sealed=True,entries=[])),
        task=a.encode(dict(nonce=nonce,state=3,instanceGuids=[])))
    final = dict(proof=a.encode(dict(schema='full300-no-supervisor-attempt-v1',nonce=nonce)),
                 prelaunch_drain=drain,ras=absent['ras'])
    phase1 = dict(schema='fresh-admin-phase1-v1',binding=bound,normalCleanupSucceeded=False,
        drain=observe('drain',drain),absence=observe('absence',final),
        waiter=observe('waiter',dict(identity=user,signalled=True,exitCode=0)),
        restoration=observe('restoration',dict(wrapperSHA256=guest['wrapperSHA256'],policy=guest['policy'],task=guest['task'],duration='PT3M')),
        eight=observe('eight',dict(base,git=admin_git(base['git']))),
        closures=observe('closures',{'original-session':dict(identity={'id':'inert'},submission='Submitted',terminal='Collected',sessionState='Closed',pending=False)}))
    p1 = a.encode(e.pack(phase1))
    cap = dict(identity=resources['captureIdentity'],health={'ExitCode':0},
               pcap=b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,65535,1),
               log='0 packets captured\n0 packets received by filter\n0 packets dropped by kernel\n')
    cap['archiveSHA256'] = a.sha(a.encode(e.pack(cap)))
    cap_raw = observe('capture',cap)
    sink = observe('sink',dict(unit='step10-prep-'+nonce,listed=[],retirement=dict(
        schema='fresh-sink-exit-v1',nonce=nonce,unit='step10-prep-'+nonce+'.service',
        contractSHA256=sink_contract.CONTRACT_SHA256,invocationId='a'*32,result='success',
        exitCode='killed',exitStatus='TERM')))
    ack = dict(schema='fresh-admin-watcher-closed-v1',binding=bound,phase1SHA256=a.sha(p1),
        captureSHA256=a.sha(cap_raw),sinkSHA256=a.sha(sink),failure='inert original failure',pendingQueries=0,normalCleanupSucceeded=False)
    watcher_raw = observe('watcher',dict(identity=watcher,ack=ack,signalled=True,exitCode=1))
    p2 = a.encode(e.pack(dict(schema='fresh-admin-phase2-v1',binding=bound,normalCleanupSucceeded=False,
        phase1SHA256=a.sha(p1),capture=cap_raw,sink=sink,watcher=watcher_raw,
        drained=observe('drained',dict(operations=['original-session'],monitorJoined=True,pendingTransports=[])))))
    return bound, resources, p1, p2


def request(bound, seq, verb, proof=b''):
    return a.encode(dict(schema='fresh-admin-request-v1',binding=bound,sequence=seq,
                         verb=verb,proofSHA256=a.sha(proof)))


class Tests(unittest.TestCase):
    def test_endpoint_rejection_releases_file_and_accepts_sha_bound_replacement(self):
        owner,_,_=self.owner();owner.fail(RuntimeError('original'))
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            class Sharing:
                """Honors deny-write/delete sharing: open handles block replacement."""
                def __init__(self):self.open=set();self.pins=[]
                def revalidate(self):pass
                def pin_source(self,path):self.pins.append(pathlib.Path(path))
                def read_once(self,path,limit):
                    self.open.add(path)
                    try:
                        raw=path.read_bytes();a.require(len(raw)<=limit,'bound');return raw
                    finally:self.open.discard(path)
                def delete(self,path):
                    if path in self.open or path in self.pins:raise PermissionError('sharing violation')
                    path.unlink()
            admission=Sharing();now=[0.0];pauses=[]
            def pause(seconds):pauses.append(seconds);now[0]+=seconds
            endpoint=bootstrap.Endpoint(root,admission,lambda h:None,lambda r:'original',
                                        clock=lambda:now[0],pause=pause)
            bad=request(owner.bound,2,'collect-original')
            first=root/('admin-request-%020d.json'%1);first.write_bytes(bad)
            self.assertIsNone(endpoint(owner))
            rejected='rejected-%020d-%s.json'%(1,a.sha(bad))
            self.assertIn(rejected,owner.journal.values)
            self.assertEqual(owner.last,0)
            # The same rejected bytes are never re-read: a bounded idle slice.
            self.assertIsNone(endpoint(owner));self.assertTrue(pauses)
            admission.delete(first)
            self.assertEqual(admission.pins,[])
            good=request(owner.bound,1,'collect-original')
            (root/('admin-request-%020d-%s.json'%(1,a.sha(bad)))).write_bytes(good)
            response=a.decode(endpoint(owner))
            self.assertEqual(response['result'],'original');self.assertEqual(owner.last,1)

    def _endpoint(self,root,collect=lambda r:'original'):
        class Admission:
            def revalidate(self):pass
            def read_once(self,path,limit):
                raw=path.read_bytes();a.require(len(raw)<=limit,'File bound');return raw
        now=[0.0]
        def pause(seconds):now[0]+=seconds
        return bootstrap.Endpoint(root,Admission(),lambda h:None,collect,clock=lambda:now[0],pause=pause)

    def test_endpoint_replacement_publication_retry_uses_cache_then_next_slot(self):
        owner,_,_=self.owner();owner.fail(RuntimeError('original'));calls=[]
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            endpoint=self._endpoint(root,lambda r:calls.append(1) or 'original')
            bad=request(owner.bound,2,'collect-original')
            (root/('admin-request-%020d.json'%1)).write_bytes(bad)
            self.assertIsNone(endpoint(owner))
            good=request(owner.bound,1,'collect-original')
            (root/('admin-request-%020d-%s.json'%(1,a.sha(bad)))).write_bytes(good)
            owner.journal.bad='response-%020d.json'%1
            with self.assertRaises(OSError):endpoint(owner)
            owner.journal.bad=None
            self.assertEqual(a.decode(endpoint(owner))['result'],'original')
            self.assertTrue(owner.requests[1]['published'])
            (root/('admin-request-%020d.json'%2)).write_bytes(request(owner.bound,2,'inspect'))
            self.assertEqual(a.decode(endpoint(owner))['sequence'],2)
            self.assertEqual(calls,[1]);self.assertEqual(owner.last,2)

    def test_endpoint_rejects_stale_copy_and_unreadable_slot(self):
        owner,_,_=self.owner();owner.fail(RuntimeError('original'))
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);endpoint=self._endpoint(root)
            one=request(owner.bound,1,'inspect')
            (root/('admin-request-%020d.json'%1)).write_bytes(one)
            endpoint(owner)
            # An older request copied into slot 2 is rejected, not republished.
            (root/('admin-request-%020d.json'%2)).write_bytes(one)
            self.assertIsNone(endpoint(owner))
            self.assertIn('rejected-%020d-%s.json'%(2,a.sha(one)),owner.journal.values)
            self.assertEqual(owner.last,1)
            # An oversized replacement is refused inside the rejection path.
            replacement=root/('admin-request-%020d-%s.json'%(2,a.sha(one)))
            replacement.write_bytes(b' '*20000)
            self.assertIsNone(endpoint(owner))
            self.assertEqual(sum(k.startswith('rejected-%020d-'%2) for k in owner.journal.values),2)
            final=root/('admin-request-%020d-%s.json'%(2,endpoint.rejected[2]))
            final.write_bytes(request(owner.bound,2,'inspect'))
            self.assertEqual(a.decode(endpoint(owner))['sequence'],2)

    def _scripted_endpoint(self,root,script):
        class Admission:
            def revalidate(self):pass
            def read_once(self,path,limit):
                if script:raise script.pop(0)
                raw=path.read_bytes();a.require(len(raw)<=limit,'File bound');return raw
        now=[0.0]
        def pause(seconds):now[0]+=seconds
        return bootstrap.Endpoint(root,Admission(),lambda h:None,lambda r:'original',clock=lambda:now[0],pause=pause)

    def test_endpoint_slot_still_being_written_is_retried_not_rejected(self):
        owner,_,_=self.owner();owner.fail(RuntimeError('original'))
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            # Each tick fails once: open-for-write, then a growing file.
            script=[a.Pending('Cannot open file')]
            endpoint=self._scripted_endpoint(root,script)
            (root/('admin-request-%020d.json'%1)).write_bytes(request(owner.bound,1,'inspect'))
            script.extend([a.Pending('File changed during read')]*1000)
            self.assertIsNone(endpoint(owner))
            self.assertFalse(any(k.startswith('rejected-') for k in owner.journal.values))
            self.assertEqual((owner.last,endpoint.rejected),(0,{}))
            script.clear()
            self.assertEqual(a.decode(endpoint(owner))['sequence'],1)

    def test_endpoint_native_io_error_is_transient_and_hold_still_rejects(self):
        owner,_,_=self.owner();owner.fail(RuntimeError('original'))
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            script=[OSError(5,'ReadFile')]*1000
            endpoint=self._scripted_endpoint(root,script)
            (root/('admin-request-%020d.json'%1)).write_bytes(request(owner.bound,1,'inspect'))
            self.assertIsNone(endpoint(owner))
            self.assertEqual((owner.last,endpoint.rejected),(0,{}))
            # Invalid content (hardlink/type) keeps its rejection.
            script[:]=[a.Hold('Reparse/type/hardlink mismatch')]
            self.assertIsNone(endpoint(owner))
            self.assertIn(1,endpoint.rejected)
            final=root/('admin-request-%020d-%s.json'%(1,endpoint.rejected[1]))
            final.write_bytes(request(owner.bound,1,'inspect'))
            self.assertEqual(a.decode(endpoint(owner))['sequence'],1)

    def test_owner_stage_failure_after_containment_is_bounded_bootstrap_failure(self):
        import admin_entry,inspect
        context=dict(nonce='n'*64,configSHA256='c'*64);aborts=[]
        def after_owner(mark):mark(object());raise RuntimeError('wiring')
        journal=Journal()
        with self.assertRaises(RuntimeError):
            admin_entry.owner_stage(journal,context,lambda:aborts.append(1),after_owner)
        record=a.decode(journal.values['bootstrap-failure.json'])
        self.assertEqual(record,dict(error='RuntimeError',stage='owner',**context))
        self.assertEqual(aborts,[1]);self.assertNotIn('administrative-hold.json',journal.values)
        def stuck():raise a.Hold('Idle containment abort unacknowledged')
        journal=Journal()
        with self.assertRaises(a.Hold):admin_entry.owner_stage(journal,context,stuck,after_owner)
        hold=a.decode(journal.values['administrative-hold.json'])
        self.assertEqual((hold['stage'],hold['ownerExists'],hold['binding']),('owner',True,context))
        # run(): the guarded stage spans containment.start() to preparation.
        source=inspect.getsource(admin_entry.run)
        start=source.index('containment.start()');stage=source.index('owner_stage(journal,dict(nonce=nonce,configSHA256=sha(raw))')
        self.assertTrue(start<source.index('def build(mark)')<source.index('Owner(bound')<stage<source.index("['preparation_entry'].execute("))
        self.assertEqual(source.count('Owner(bound'),1)

    def test_shared_retirement_ledger_dispatches_once_and_refuses_changed_bytes(self):
        owner,_,_=self.owner();calls=[]
        with tempfile.TemporaryDirectory() as directory:
            owner.journal.root=pathlib.Path(directory)
            class Transport:
                def __init__(self,root,*args,**kwargs):self.children=[]
                def observe(self,argv,*args,data=b'',**kwargs):calls.append((list(argv),data));return b'stopped'
            remote=OriginalTransports(owner,transport=Transport)
            commands=sink_contract.retirement_commands(owner.bound['nonce'],'/inert/capture.py')
            command,data=commands['admin-capture-confirm']
            self.assertEqual(remote.retire('admin-capture-confirm',['ssh',command],data),b'stopped')
            # The Handoff uses the same ledger: attempted means never sent again.
            self.assertIsNone(remote.retire('admin-capture-confirm',['ssh',command],data))
            with self.assertRaises(a.Hold):remote.retire('admin-capture-confirm',['ssh',command],data+b' ')
            remote.attempts.add('admin-sink-stop')
            with self.assertRaises(a.Hold):remote.retire('admin-sink-stop',['ssh',commands['admin-sink-stop'][0]])
            self.assertEqual(calls,[(['ssh',command],data)])

    def test_not_dispatched_retirement_resolves_by_readback_without_resend(self):
        owner,_,_=self.owner();calls=[]
        with tempfile.TemporaryDirectory() as directory:
            owner.journal.root=pathlib.Path(directory)
            class Transport:
                def __init__(self,root,*args,**kwargs):self.children=[]
                def observe(self,argv,*args,**kwargs):calls.append(list(argv));return b'stopped'
            remote=OriginalTransports(owner,transport=Transport)
            command,data=sink_contract.retirement_commands(owner.bound['nonce'],'/inert/capture.py')['admin-capture-stop']
            owner.journal.bad='transport-000001.json'
            with self.assertRaises(OSError):remote.retire('admin-capture-stop',['ssh',command],data)
            owner.journal.bad=None
            # The capture ended by itself; the readback proof resolves the key.
            remote.resolve_retirement('admin-capture-stop','a'*64)
            self.assertEqual(remote.entries[0]['state'],'Resolved')
            self.assertFalse(a.decode(owner.journal.values['transport-resolution-000001.json'])['dispatched'])
            self.assertIsNone(remote.retire('admin-capture-stop',['ssh',command],data))
            self.assertEqual(calls,[])

    def test_bootstrap_failure_without_owner_records_terminal_hold(self):
        import admin_entry
        context=dict(nonce='n'*64,configSHA256='c'*64)
        def stuck():raise a.Hold('Idle containment abort unacknowledged; original child retained')
        journal=Journal()
        with self.assertRaises(a.Hold):
            admin_entry.bootstrap_failure(journal,context,'owner',RuntimeError('inert owner'),stuck)
        hold=a.decode(journal.values['administrative-hold.json'])
        self.assertEqual((hold['schema'],hold['ownerExists'],hold['stage']),('fresh-admin-hold-v1',False,'owner'))
        self.assertIn('bootstrap-failure.json',journal.values)
        # A positive idle abort is a clean bootstrap failure, not a HOLD.
        journal=Journal();admin_entry.bootstrap_failure(journal,context,'containment',OSError('x'),lambda:None)
        self.assertNotIn('administrative-hold.json',journal.values)

    def test_transport_failure_before_spawn_is_not_dispatched_and_reservable(self):
        owner,_,_=self.owner();calls=[]
        with tempfile.TemporaryDirectory() as directory:
            owner.journal.root=pathlib.Path(directory)
            status=[255]
            class Transport:
                def __init__(self,root,*args,**kwargs):self.children=[];self.root=root
                def observe(self,argv,*args,mutation=True,**kwargs):
                    calls.append(list(argv))
                    if argv==['read']:
                        self.children.append(dict(process=SimpleNamespace(poll=lambda:status[0])))
                        raise RuntimeError('inert ssh exit 255')
                    return b'done'
            remote=OriginalTransports(owner,transport=Transport)
            owner.journal.bad='transport-000001.json'
            with self.assertRaises(OSError):remote.fixed('admin-capture-stop',['stop'])
            self.assertIsNone(remote.pending);self.assertEqual(remote.entries[0]['state'],'NotDispatched')
            owner.journal.bad=None
            self.assertEqual(remote.fixed('admin-capture-stop',['stop']),b'done')
            self.assertEqual(remote.fixed('admin-capture-stop',['stop']),b'done')
            # A terminal failed read releases the slot; a fresh read may follow.
            with self.assertRaises(RuntimeError):remote.fixed('admin-read-x-0',['read'],mutation=False)
            self.assertIsNone(remote.pending);self.assertEqual(remote.entries[-1]['state'],'Failed')
            self.assertEqual(calls,[['stop'],['read']])
            self.assertEqual(len(remote.entries),3)

    def test_resident_publish_failure_before_visibility_rolls_back_sequence(self):
        with tempfile.TemporaryDirectory() as directory:
            owner,_,_=self.owner();owner.journal.root=pathlib.Path(directory)
            resident=ResidentRPC.__new__(ResidentRPC)
            resident.owner=owner;resident.root=pathlib.Path(directory);resident.lock=threading.RLock()
            resident.sequence=0;resident.pending=None;resident.fixed_requests={};resident.results={}
            resident.not_dispatched=[]
            fault=[True];collected=[]
            def publish(name,raw):
                if fault[0] and name.startswith('resident-request-'):raise OSError('inert flush before write')
                (resident.root/name).write_bytes(raw)
            resident._publish=publish
            resident.collect=lambda seconds=30:collected.append(resident.pending['sequence']) or b'{}'
            with self.assertRaises(OSError):resident.fixed('phase1-guest','guest',b'{}')
            self.assertEqual((resident.sequence,resident.pending,resident.fixed_requests),(0,None,{}))
            self.assertEqual(len(resident.not_dispatched),1)
            fault[0]=False
            resident.fixed('phase1-guest','guest',b'{}')
            self.assertEqual(collected,[1])
            self.assertTrue((resident.root/('resident-request-%020d.json'%1)).is_file())

    def test_normal_release_ack_is_distinct_terminal_hold(self):
        owner,_,_=self.owner()
        with tempfile.TemporaryDirectory() as directory:
            owner.journal.root=pathlib.Path(directory)
            (owner.journal.root/'watcher-release-ack.json').write_bytes(b'{}')
            Handoff(owner)
            def body(resources):raise RuntimeError('original failure after normal release')
            def serve(o):o.request(request(o.bound,1,'advance'))
            result=a.run_preparation(owner,lambda r:None,body,lambda r:None,serve,pause=lambda s:None)
            self.assertEqual(result,'ADMINISTRATIVE_HOLD');self.assertEqual(owner.state,'HOLD')
            hold=a.decode(owner.journal.values['administrative-hold.json'])
            self.assertFalse(hold['normalCleanupSucceeded']);self.assertIsNone(owner.settlement)

    def test_resident_readback_may_repeat_after_failed_but_policy_never(self):
        import base64
        with tempfile.TemporaryDirectory() as directory:
            owner,_,_=self.owner();owner.journal.root=pathlib.Path(directory)
            resident=ResidentRPC.__new__(ResidentRPC)
            resident.owner=owner;resident.root=pathlib.Path(directory);resident.lock=threading.RLock()
            resident.sequence=0;resident.pending=None;resident.fixed_requests={};resident.results={}
            resident.not_dispatched=[];states=['Failed','Collected','Failed'];submitted=[]
            resident._publish=lambda name,raw:(resident.root/name).write_bytes(raw)
            def collect(seconds=30):
                p=resident.pending;state=states.pop(0);submitted.append(p['operation'])
                resident.results[p['sequence']]=dict(state=state,requestSHA256=p['requestSHA256'],
                    output=base64.b64encode(b'{}').decode());resident.pending=None
                a.require(state=='Collected','Original resident operation failed')
                return b'{}'
            resident.collect=collect
            with self.assertRaises(a.Hold):resident.fixed('phase1-guest','guest',b'{}')
            self.assertEqual(resident.fixed('phase1-guest','guest',b'{}'),b'{}')
            self.assertEqual(resident.fixed('phase1-guest','guest',b'{}'),b'{}')
            with self.assertRaises(a.Hold):resident.fixed('phase1-policy','restore-session-policy',b'{}')
            with self.assertRaises(a.Hold):resident.fixed('phase1-policy','restore-session-policy',b'{}')
            self.assertEqual(submitted,['guest','guest','restore-session-policy'])

    def test_finalizer_failure_after_normal_body_is_terminal_hold(self):
        owner,_,_=self.owner()
        closes=[]
        def close():closes.append(1);raise OSError('inert resident close failure')
        owner.resources['resident']=SimpleNamespace(close_session=close,finish=lambda receipt:None)
        source=b"held=object()"
        result=execute(owner,source,a.sha(source),'inert.py',lambda o:self.fail('served after normal body'))
        self.assertEqual(result,'ADMINISTRATIVE_HOLD');self.assertEqual(closes,[1])
        self.assertIsNotNone(owner.resources['held']);self.assertIn('OSError',owner.failure)
        hold=a.decode(owner.journal.values['administrative-hold.json'])
        self.assertEqual(hold['reason'],'Normal finalizer failed after completed body')

    def test_resident_spawn_failure_and_idle_abort_have_finite_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            b,r,_,_=fixture();root=pathlib.Path(directory)
            class Admission(Pins):
                def create_root(self,path):path.mkdir();return path
            owner=a.Owner(b,a.Journal(root,Admission()),r,e.validate_phase1,e.validate_phase2)
            r['entryInventory']={name:False for name in r['entryInventory']}
            r['original_remote_transport']=OriginalTransports(owner)
            def popen(*args,**kwargs):raise OSError('inert spawn failure')
            with self.assertRaises(OSError):
                ResidentRPC(owner,root,popen=popen,environment=lambda path:{'PSModulePath':'INERT'})
            self.assertEqual(r['operations']['resident']['submission'],'NotDispatched')
            receipt=dict(context={'nonce':b['nonce']},identity=b['containmentOwner'])
            r['containment']=SimpleNamespace(abort_idle=lambda:receipt)
            Handoff(owner);owner.fail(RuntimeError('setup failure'))
            owner.request(request(b,1,'advance'))
            self.assertEqual(owner.state,'ABORTED_NEVER_SUBMITTED')
            containment=Containment(root,root,Pins(),'a'*64,'b'*64,'c'*64,b'{}')
            now=[0.0];calls=[]
            def abort():calls.append(1);raise FileNotFoundError('no receipt')
            containment.abort_idle=abort
            def pause(seconds):now[0]+=seconds
            with self.assertRaises(a.Hold):containment.abort_idle_bounded(1,clock=lambda:now[0],pause=pause)
            self.assertTrue(1<len(calls)<20)

    def test_reader_closure_binds_creation_time_not_reused_pid(self):
        owner,_,_=self.owner()
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            reader=cancellation.Transport.__new__(cancellation.Transport)
            reader.label='reader';reader.stdout=root/'reader.stdout';reader.administrative_owner=owner
            reader.identity=dict(pid=7,startFiletime=125);reader.process=SimpleNamespace(poll=lambda:0)
            closed=dict(nonce=owner.bound['nonce'],pid=7,instanceId='original',state='Closed')
            for creation,accepted in (('999',False),('125',True)):
                (root/'reader.session-closed.json').write_bytes(a.encode(dict(closed,creationFileTime=creation)))
                if accepted:self.assertEqual(reader.administrative_closure()['sessionState'],'Closed')
                else:
                    with self.assertRaises(a.Hold):reader.administrative_closure()

    def test_terminal_retirement_failure_requires_independent_proof_no_replay(self):
        owner,_,_=self.owner();status=[None];calls=[]
        with tempfile.TemporaryDirectory() as directory:
            owner.journal.root=pathlib.Path(directory)
            class Transport:
                def __init__(self,root,*args,**kwargs):self.root=root;self.children=[]
                def observe(self,argv,*args,**kwargs):
                    calls.append(list(argv))
                    if argv==['inert-read']:return b'positive independent proof'
                    path=self.root/'stdout';path.write_bytes(b'original error output')
                    self.children.append(dict(process=SimpleNamespace(poll=lambda:status[0]),handle=object(),
                        record=dict(identity={'pid':1},files={'stdout':str(path)})))
                    raise TimeoutError('inert original effect observation lost')
            remote=OriginalTransports(owner,transport=Transport)
            with self.assertRaises(TimeoutError):remote.fixed('admin-capture-stop',['inert-stop'])
            with self.assertRaises(a.Hold):remote.permit_retirement_readback()
            status[0]=1;remote.permit_retirement_readback()
            with self.assertRaises(a.Hold):remote.fixed('admin-capture-stop',['inert-stop'])
            proof=remote.fixed('admin-read-capture-health',['inert-read'],mutation=False)
            remote.resolve_retirement('admin-capture-stop',a.sha(proof))
            self.assertEqual(remote.fixed('admin-capture-stop',['inert-stop']),b'original error output')
            self.assertEqual(calls,[['inert-stop'],['inert-read']])

    def test_mailbox_publication_failure_uses_original_resident_cache(self):
        import base64
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);nonce='a'*64;calls=[]
            resident=ResidentRPC.__new__(ResidentRPC);resident.pending=None;resident.results={}
            def original(mode,path):
                calls.append(mode);command=path.read_bytes();value=a.decode(command)
                raw=a.encode(dict(schema='full300-owner-response-v1',nonce=nonce,
                    configSHA256=value['configSHA256'],seq=value['seq'],commandSHA256=a.sha(command),
                    outcome='accepted',state='CLOSED',owner=None,refs=[],error=None))
                resident.results[1]=dict(requestSHA256=a.sha(command),state='Collected',
                    output=base64.b64encode(raw).decode())
                return raw
            client=rpc.MailboxClient(root,nonce,a.encode({'nonce':nonce}),original)
            freeze=rpc.freeze;fault=[True]
            def publish(path,raw):
                result=freeze(path,raw)
                if pathlib.Path(path).parent.name=='receipts' and fault[0]:
                    fault[0]=False;raise OSError('inert acknowledgement loss after exact receipt write')
                return result
            with patch.object(rpc,'freeze',publish):
                with self.assertRaises(OSError):client.command('cleanup',{})
                retained=(root/'receipts/00000001.json').read_bytes()
                resources=dict(resident=resident,stage=SimpleNamespace(thread=None,adapter=SimpleNamespace(client=client)))
                collect_original(resources)
                self.assertEqual((root/'receipts/00000001.json').read_bytes(),retained)
                client.once('cleanup',{})
            self.assertEqual(calls,['submit']);self.assertIsNone(client.pending)

    def test_sink_poststop_literal_roundtrip_and_semantic_retirement(self):
        import ast,shlex,io,os
        b,r,_,_=fixture();nonce=b['nonce']
        command=sink_contract.start_command(nonce,'/home/lab/step9-'+'b'*64)
        argv=shlex.split(command)
        self.assertIn('--property=SendSIGKILL=no',argv)
        post=next(x.split('=',2)[2] for x in argv if x.startswith('--property=ExecStopPost='))
        tokens=shlex.split(post);self.assertEqual(tokens[:2],['/usr/bin/python3','-c'])
        tree=ast.parse(tokens[2]);literal=tree.body[0].value.args[0].args[0].value
        program=bytes.fromhex(literal).decode()
        stream=io.BytesIO()
        class File:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def write(self,raw):return stream.write(raw)
            def flush(self):pass
            def fileno(self):return 123
        def opened(path,mode):
            self.assertEqual(path,'/var/lib/step8/run-'+nonce+'/sink-exit.json')
            self.assertEqual(mode,'xb');return File()
        with patch.dict(os.environ,{'INVOCATION_ID':'b'*32,'SERVICE_RESULT':'success',
                                    'EXIT_CODE':'killed','EXIT_STATUS':'TERM'},clear=True),patch.object(os,'fsync',lambda fd:None):
            exec(compile(program,'inert post-stop literal','exec'),{'open':opened})
        sink=dict(unit='step10-prep-'+nonce,listed=[],retirement=a.decode(stream.getvalue()))
        e.validate_sink(sink,b,r)
        sink['retirement']['result']='timeout'
        with self.assertRaises(a.Hold):e.validate_sink(sink,b,r)

    def test_never_entered_requires_original_inventory_not_missing_files(self):
        b,r,p1,_=fixture();v=e.unpack(a.decode(p1));r['waiterIdentity']=None
        r['entryInventory'].update(guestAttempted=False,preparationAttempted=False,sinkAttempted=False)
        replacements=dict(drain=dict(schema='fresh-admin-never-entered-v1',nonce=b['nonce']),
            absence=dict(schema='fresh-admin-no-guest-effect-v1',nonce=b['nonce']),waiter=dict(neverSubmitted=True))
        for name,value in replacements.items():
            envelope=a.decode(v[name]);envelope['value']=e.pack(value);v[name]=a.encode(envelope)
            r['observations'][name]['sha256']=a.sha(v[name])
        raw=a.encode(e.pack(v));e.validate_phase1(raw,b,r)
        e.validate_sink(dict(unit='step10-prep-'+b['nonce'],neverSubmitted=True),b,r)
        r['entryInventory']['preparationAttempted']=True
        with self.assertRaises(a.Hold):e.validate_phase1(raw,b,r)

    def test_bootstrap_abort_has_distinct_positive_result_and_no_restore_claim(self):
        owner,_,_=self.owner();r=owner.resources
        r['entryInventory']={name:False for name in r['entryInventory']}
        r['original_remote_transport']=SimpleNamespace(entries=[],pending=None)
        calls=[]
        def abort():
            calls.append(1)
            if len(calls)==1:raise a.Hold('original idle watcher still pending')
            return dict(context={'nonce':owner.bound['nonce']},identity=owner.bound['containmentOwner'])
        r['containment']=SimpleNamespace(abort_idle=abort)
        Handoff(owner);owner.fail(RuntimeError('setup failure before operational effects'))
        first=request(owner.bound,1,'advance')
        owner.request(first);owner.request(first)
        self.assertEqual(calls,[1]);self.assertEqual(owner.state,'FAILED')
        owner.request(request(owner.bound,2,'advance'))
        self.assertEqual(owner.state,'ABORTED_NEVER_SUBMITTED')
        self.assertIsNone(owner.settlement)
        self.assertNotIn('administrative-settled.json',owner.journal.values)

    def test_effect_reservation_failure_resumes_only_original_unentered_callable(self):
        owner,_,_=self.owner();calls=[]
        owner.journal.bad='effect-original.json'
        with self.assertRaises(OSError):owner.effect_once('original',lambda:calls.append('original'))
        self.assertEqual(calls,[]);owner.journal.bad=None
        owner.resume_reserved('original')
        with self.assertRaises(a.Hold):owner.resume_reserved('original')
        self.assertEqual(calls,['original'])

    def test_watcher_query_timeout_retains_original_child_no_kill_or_resubmit(self):
        status=[None];calls=[]
        with tempfile.TemporaryDirectory() as directory:
            class Transport:
                def __init__(self,root,*args,**kwargs):self.root=root;self.children=[]
                def observe(self,*args,**kwargs):
                    calls.append('submit');path=self.root/'stdout';path.write_bytes(b'{"original":true}')
                    self.children.append(dict(process=SimpleNamespace(poll=lambda:status[0]),handle=object(),
                        record=dict(identity={'pid':1},files={'stdout':str(path)})))
                    raise TimeoutError('inert original observation expiry')
            query=Query(directory,['inert'],transport=Transport)
            with self.assertRaises(TimeoutError):query()
            with self.assertRaises(a.Hold):query()
            self.assertIsNotNone(query.unresolved());status[0]=0
            self.assertEqual(query()['value'],{'original':True})
            self.assertIsNone(query.unresolved());self.assertEqual(calls,['submit'])

    def test_idle_containment_reservation_original_identity_and_positive_abort(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);status=[None];calls=[]
            original=SimpleNamespace(pid=17,poll=lambda:status[0])
            containment=Containment(root,root,Pins(),'a'*64,'b'*64,'c'*64,b'{}')
            identity=dict(pid=17,creationFileTime='123',imageSHA256=a.sha(pathlib.Path(sys.executable).read_bytes()))
            def spawn(*args,**kwargs):
                self.assertTrue((root/'containment-start-reserved.json').is_file());calls.append(1)
                (root/'containment-ready.json').write_bytes(a.encode(dict(context=containment.context,identity=identity)))
                return original
            containment.start(popen=spawn,identity=lambda p:SimpleNamespace(creation=123,exe=sys.executable))
            with self.assertRaises(FileNotFoundError):containment.abort_idle()
            self.assertIs(containment.process,original)
            (root/'containment-aborted.json').write_bytes(a.encode(dict(context=containment.context,identity=identity)))
            status[0]=1;containment.abort_idle();containment.abort_idle()
            self.assertEqual(calls,[1])

    def test_late_original_transport_collection_never_spawns(self):
        owner,_,_=self.owner();status=[None];calls=[]
        with tempfile.TemporaryDirectory() as directory:
            owner.journal.root=pathlib.Path(directory)
            class Original:
                def __init__(self,root,*args,**kwargs):
                    self.children=[];self.root=root
                def observe(self,*args,**kwargs):
                    calls.append('submit')
                    path=self.root/'original.stdout';path.write_bytes(b'original response')
                    self.children.append(dict(process=SimpleNamespace(poll=lambda:status[0]),
                        handle=object(),record=dict(identity={'pid':123},files={'stdout':str(path)})))
                    raise TimeoutError('original observer expired')
            remote=OriginalTransports(owner,transport=Original)
            with self.assertRaises(TimeoutError):remote(['inert'],.1)
            with self.assertRaises(a.Hold):remote.collect_original()
            with self.assertRaises(a.Hold):remote(['inert'],.1)
            status[0]=0
            owner.journal.bad='transport-late-000001.json'
            with self.assertRaises(OSError):remote.collect_original()
            owner.journal.bad=None
            self.assertEqual(remote.collect_original(),b'original response')
            self.assertEqual(calls,['submit'])
            self.assertFalse(a.decode(owner.journal.values['transport-late-000001.json'])['remoteClosureProven'])

    def test_collect_original_cancellation_retains_pending_objects(self):
        status=[None];calls=[];original=SimpleNamespace(poll=lambda:status[0],
            result=lambda:(calls.append('collect') or {'nonce':'n','task':{'state':3}}))
        state=dict(nonce='n',pending={'drain-status':original},owners={},local={},completed=[],status={})
        resources={'cancellation_state':state}
        self.assertEqual(collect_original(resources)['controller'][0]['state'],'Pending')
        self.assertIs(state['pending']['drain-status'],original)
        status[0]=0
        self.assertEqual(collect_original(resources)['controller'][0]['state'],'Collected')
        self.assertIs(state['completed'][0][1],original)
        self.assertEqual(collect_original(resources)['controller'],[])
        self.assertEqual(calls,['collect'])

    def owner(self):
        b,r,p1,p2=fixture()
        return a.Owner(b,Journal(),r,e.validate_phase1,e.validate_phase2),p1,p2

    def test_complete_failed_run_and_cached_response(self):
        owner,p1,p2=self.owner();owner.fail(RuntimeError('original failure'))
        one=request(owner.bound,1,'phase1',p1)
        owner.request(one,phase1=p1)
        two=request(owner.bound,2,'settle',p2)
        response=owner.request(two,phase2=p2)
        self.assertEqual(owner.state,'SETTLED')
        self.assertFalse(owner.settlement['normalCleanupSucceeded'])
        self.assertIn('original failure',owner.settlement['failure'])
        self.assertEqual(owner.request(two,phase2=b'changed'),response)

    def test_request_reservation_precedes_effect_and_survives_error(self):
        owner,_,_=self.owner();owner.fail(RuntimeError('original'))
        calls=[]
        def collect(resources):
            self.assertIn('request-00000000000000000001.json',owner.journal.values)
            self.assertIs(resources,owner.resources)
            calls.append(1);raise OSError('lost result')
        req=request(owner.bound,1,'collect-original')
        first=owner.request(req,collect=collect)
        self.assertEqual(a.decode(first)['result']['observation'],'unresolved')
        self.assertEqual(owner.request(req,collect=collect),first)
        self.assertEqual(calls,[1])
        owner.request(request(owner.bound,2,'collect-original'),collect=lambda r:'late original result')
        self.assertEqual(calls,[1])

    def test_reservation_flush_failure_has_zero_effects(self):
        owner,_,_=self.owner();owner.fail(RuntimeError('original'))
        owner.journal.bad='request-00000000000000000001.json'
        calls=[];req=request(owner.bound,1,'collect-original')
        response=owner.request(req,collect=lambda r:calls.append(1))
        self.assertFalse(a.decode(response)['result']['dispatched'])
        owner.journal.bad=None
        self.assertEqual(owner.request(req,collect=lambda r:calls.append(1)),response)
        self.assertEqual(calls,[])
        owner.request(request(owner.bound,2,'collect-original'),collect=lambda r:calls.append(2))
        self.assertEqual(calls,[2])

    def test_response_publication_failure_does_not_repeat_collection(self):
        owner,_,_=self.owner();owner.fail(RuntimeError('original'))
        owner.journal.bad='response-00000000000000000001.json';calls=[]
        req=request(owner.bound,1,'collect-original')
        with self.assertRaises(OSError):owner.request(req,collect=lambda r:calls.append(1))
        owner.journal.bad=None
        owner.request(req,collect=lambda r:calls.append(2))
        self.assertEqual(calls,[1])

    def test_settlement_publication_failure_finishes_without_action_reentry(self):
        owner,p1,p2=self.owner();owner.fail(RuntimeError('original'))
        owner.request(request(owner.bound,1,'phase1',p1),phase1=p1)
        owner.journal.bad='administrative-settled.json'
        req=request(owner.bound,2,'settle',p2)
        with self.assertRaises(OSError):owner.request(req,phase2=p2)
        self.assertEqual(owner.state,'PHASE2')
        self.assertIsNone(owner.settlement)
        owner.validate_phase2=lambda *args:self.fail('Repeated validator/action')
        owner.journal.bad=None
        owner.request(req,phase2=b'ignored replay argument')
        self.assertEqual(owner.state,'SETTLED')

    def test_invalid_pure_proof_does_not_consume_sequence(self):
        owner,p1,p2=self.owner();owner.fail(RuntimeError('original'))
        bad=b'{}'
        with self.assertRaises(a.Hold):owner.request(request(owner.bound,1,'phase1',bad),phase1=bad)
        self.assertEqual(owner.last,0)
        owner.request(request(owner.bound,1,'phase1',p1),phase1=p1)

    def test_real_entry_keeps_namespace_on_setup_body_finalizer_aborted(self):
        # Actual execute/run_preparation boundaries, with inert phase bodies.
        cases=[b"held=object()\nraise OSError('setup')",
               b"held=object()\ntry: raise ValueError('body')\nfinally: marker='once'",
               b"held=object()\ntry: marker='body'\nfinally: raise OSError('finalizer')",
               b"held=object()\nstage=type('Stage',(),{'lifecycle':'ABORTED'})()"]
        for source in cases:
            owner,p1,p2=self.owner();seen=[]
            def endpoint(o):
                seen.append(o.resources['held'])
                o.request(request(o.bound,1,'phase1',p1),phase1=p1)
                o.request(request(o.bound,2,'settle',p2),phase2=p2)
            result=execute(owner,source,a.sha(source),'inert.py',endpoint)
            self.assertEqual(result,'ADMINISTRATIVELY_RESTORED_FAILED_RUN')
            self.assertIs(seen[0],owner.resources['held'])
            self.assertIsNotNone(owner.failure)

    def test_exact_preparation_body_actual_setup_and_finally_paths(self):
        source_path=pathlib.Path(__file__).with_name('preparation_body.py')
        source=source_path.read_bytes()
        class Thread:
            def __init__(self,*args,**kwargs):pass
            def start(self):pass
            def join(self,*args,**kwargs):pass
            def is_alive(self):return False
        class Adapter:
            def __init__(self,*args,**kwargs):pass
            def bind_preparation(self,process,command):self.original=process
        for point in ('setup','body','finalizer'):
            with tempfile.TemporaryDirectory() as directory:
                owner,p1,p2=self.owner();owner.journal.root=pathlib.Path(directory)
                ssh_pins=[]
                class Recording(Pins):
                    # Never reads the host key directory; records the bound hash only.
                    def pin_readonly_source(self,path,expected,limit):
                        ssh_pins.append((pathlib.Path(path).name,expected))
                        return b'',dict(path=str(path),sha256=expected,components=[])
                owner.journal.admission=Recording()
                owner.resources['sshInputs']=dict(knownHostsSHA256='1'*64,clientSHA256='2'*64)
                resident=SimpleNamespace(helper=lambda *args:None)
                owner.resources.update(resident=resident,sshExecutable='INERT-SSH',captureSources={
                    'capture-supervisor.py':b'capture source','sinks.py':b'sink source'})
                calls=[]
                argvs=[]
                def remote(argv,seconds,mutation=True):
                    command=argv[-1];calls.append(command);argvs.append(list(argv))
                    if command.endswith('/capture-supervisor.py'):return b'capture source'
                    if command.endswith('/sinks.py'):return b'sink source'
                    if ' start ' in command and point=='setup':raise OSError('original setup failure')
                    if ' status ' in command:return a.encode(dict(Healthy=True,LiveIdentityHealthy=True,Identity={'inert':1}))
                    return b'inert response'
                owner.resources['original_remote_transport']=remote
                process=SimpleNamespace(returncode=0)
                owner.resources['independent']=process
                (owner.journal.root/'host-supervisor-identity.json').write_bytes(b'{}')
                def popen(*args,**kwargs):
                    (owner.journal.root/'host-supervisor-identity.json').write_bytes(b'{}')
                    return process
                owner.resources['spawn_owned']=popen
                class Stage:
                    def __init__(self,*args,**kwargs):self.adapter=kwargs['adapter'];self.lifecycle='NEW'
                    def start(self):
                        self.lifecycle='ABORTED' if point=='body' else 'RUNNING'
                        if point=='body':raise OSError('original body failure')
                    def before_restore(self):pass
                class BoundaryObserved(BaseException):pass
                retained=[]
                def endpoint(o):
                    retained.append((o,o.resources.get('administrative_owner'),o.resources.get('stage')))
                    # End this failure-boundary test without claiming unrelated
                    # synthetic fixture proofs describe this preparation body.
                    raise BoundaryObserved()
                with patch.object(protected_stage,'Stage',Stage),patch.object(rpc,'Adapter',Adapter),\
                     patch.object(cancellation,'control',lambda *args,**kwargs:True),\
                     patch.object(threading,'Thread',Thread),patch.object(subprocess,'Popen',popen),\
                     patch.object(time,'sleep',lambda seconds:None),patch('sys.argv',['preparation.py']):
                    with self.assertRaises(BoundaryObserved):
                        execute(owner,source,a.sha(source),source_path,endpoint)
                self.assertIs(retained[0][0],retained[0][1])
                self.assertIs(retained[0][2],owner.resources['stage'])
                self.assertIsNotNone(owner.failure)
                self.assertEqual(sum(' start ' in x for x in calls),1,owner.failure)
                self.assertFalse(any(' stop ' in x for x in calls))
                self.assertEqual(ssh_pins,[('known_hosts2','1'*64),('client2','2'*64)])
                # No user/system ssh_config: '-F none' right after the pinned image,
                # and the Handoff receives exactly the body argv prefix.
                self.assertTrue(argvs and all(x[:3]==['INERT-SSH','-F','none'] for x in argvs))
                self.assertTrue(all(x[:-1]==owner.resources['ssh'] for x in argvs))
                self.assertTrue(owner.resources['capture'].endswith('/capture-supervisor.py'))
                self.assertTrue(any(owner.resources['capture'] in x for x in calls))
                self.assertIn('readonly-ssh-pins.json',owner.journal.values)

    def test_all_phase_proofs_missing_or_rebound_refuse(self):
        b,r,p1,p2=fixture()
        for raw,names,validate in [(p1,('drain','absence','waiter','restoration','closures','eight'),lambda v:e.validate_phase1(v,b,r)),
            (p2,('capture','sink','watcher','drained'),lambda v:e.validate_phase2(v,p1,b,r))]:
            for name in names:
                value=a.decode(raw);del value[name]
                with self.assertRaises((a.Hold,KeyError)):validate(a.encode(value))
                value=a.decode(raw);value[name]={'$bytes':'e30='}
                with self.assertRaises((a.Hold,KeyError)):validate(a.encode(value))
        wrong=copy.deepcopy(b);wrong['nonce']='f'*64
        with self.assertRaises(a.Hold):e.validate_phase1(p1,wrong,r)
        r['operations']['original-session']['submission']='Unknown'
        with self.assertRaises(a.Hold):e.validate_phase1(p1,b,r)

    def test_eight_predicates_not_just_hashes(self):
        b,r,p1,p2=fixture();base=e.unpack(a.decode(r['baseline']))
        good=dict(base,git=admin_git(base['git']))
        e.eight_proofs(copy.deepcopy(good),base,CHECKOUT)
        for key in s.PROOFS:
            proofs=copy.deepcopy(good);proofs[key]=b'wrong' if type(proofs[key]) is bytes else {}
            with self.assertRaises((a.Hold,s.Hold,KeyError,TypeError,ValueError)):
                e.eight_proofs(proofs,base,CHECKOUT)
        # Administrative git proof: no status field; HEAD/branch/files/worktree exact.
        for mutate in (lambda g:g.update(status=base['git']['status']),lambda g:g.update(HEAD='b'*40),
                       lambda g:g.update(branch='other'),lambda g:g['files'].update({'inert/0':'0'*64}),
                       lambda g:g['worktree'].update(ref='git'),lambda g:g['worktree'].update(gitDir=r'C:\other'),
                       lambda g:g.pop('worktree')):
            proofs=copy.deepcopy(good);mutate(proofs['git'])
            with self.assertRaises(a.Hold):e.eight_proofs(proofs,base,CHECKOUT)
        with self.assertRaises(a.Hold):e.eight_proofs(copy.deepcopy(good),base,dict(CHECKOUT,commonDir=r'C:\x'))

    def test_preentry_exclusion_requires_original_attempt_inventory(self):
        for key in ('supervisorAttempted','stockDeploymentAttempted','stockPermitAttempted'):
            b,r,p1,p2=fixture();r['originalRun'][key]=True
            with self.assertRaises(a.Hold):e.validate_phase1(p1,b,r)

    def test_watcher_pending_no_ack_then_positive_distinct_exit(self):
        b,r,p1,p2=fixture();v=e.unpack(a.decode(p2));published=[]
        req=a.encode(dict(schema='fresh-admin-watcher-request-v1',binding=b,phase1SHA256=a.sha(p1),
            captureSHA256=a.sha(v['capture']),sinkSHA256=a.sha(v['sink'])))
        state={'failure':'original failure'}
        args=(state,req,p1,v['capture'],v['sink'],b,r)
        with self.assertRaises(a.Hold):w.administrative_tick(*args,object(),lambda *x:published.append(x))
        self.assertEqual(published,[])
        self.assertTrue(w.administrative_tick(*args,None,lambda *x:published.append(x)))
        self.assertEqual(state['exitCode'],1)
        self.assertEqual(published[0][0],'administrative-watcher-closed.json')
        self.assertFalse(a.decode(published[0][1])['normalCleanupSucceeded'])

    def test_acl_decision_exact_masks_owner_no_foreign_writes(self):
        sid=s.SID;aces=[(0,3,0x1f01ff,x) for x in (sid,n.SYSTEM,n.ADMIN)]
        n.validate_acl(sid,True,aces,sid,True)
        cases=[('S-1-1-0',True,aces),(sid,False,aces),(sid,True,aces+[(0,3,1,'S-1-1-0')]),
               (sid,True,[(0,3,0x1f01fe,sid),*aces[1:]])]
        for owner,protected,rows in cases:
            with self.assertRaises(a.Hold):n.validate_acl(owner,protected,rows,sid,True)
        with self.assertRaises(a.Hold):n.validate_acl(sid,False,[(0,0,0x10,'S-1-1-0')],sid,False)

    def test_acl_ancestor_stock_drive_root_accepted(self):
        sid=s.SID;users='S-1-5-32-545';auth='S-1-5-11'
        stock=[(0,3,0x1f01ff,n.ADMIN),(0,3,0x1f01ff,n.SYSTEM),(0,3,0x1200a9,users),
               (0,0x0b,0x1301bf,auth),(0,0,0x4,auth)]
        n.validate_acl(n.SYSTEM,False,stock,sid,False,ancestor=True)
        for extra in [(0,0,0x40,auth),(0,0,0x40000,'S-1-1-0'),(0,3,0x1301bf,auth),
                      (0,0,0x10000,auth),(5,0x0b,0x4,auth)]:
            with self.assertRaises(a.Hold):n.validate_acl(n.SYSTEM,False,stock+[extra],sid,False,ancestor=True)
        with self.assertRaises(a.Hold):n.validate_acl(n.SYSTEM,True,stock,sid,True)
        # The relaxed mask is for true ancestors only: as a leaf or code
        # directory the same add-file/add-subdirectory ACE refuses.
        with self.assertRaises(a.Hold):n.validate_acl(n.SYSTEM,False,stock,sid,False)
        for bit in (0x2,0x4):
            n.validate_acl(n.SYSTEM,False,[(0,0,bit,auth)],sid,False,ancestor=True)
            with self.assertRaises(a.Hold):n.validate_acl(n.SYSTEM,False,[(0,0,bit,auth)],sid,False)
        self.assertEqual(n.MUTATION,0x500d0156);self.assertEqual(n.ANCESTOR_MUTATION,0x500d0150)

    def test_code_directory_and_leaf_use_full_mask(self):
        sid=s.SID;auth='S-1-5-11';root=r'C:\Adm';driver=root+r'\runtime\driver';leaf=driver+r'\x.py'
        trusted=[(0,3,0x1f01ff,n.SYSTEM),(0,3,0x1f01ff,n.ADMIN)]
        def volume():
            v=FakeVolume(leaf,b'x',trusted+[(0,0,0x6,auth)]);return v
        # Plain ancestors accept add-file; the leaf itself refuses it.
        with self.assertRaises(a.Hold):volume().install(sid).pin_source(leaf)
        v=volume();v.entries[leaf]['acl']=list(trusted);obj=v.install(sid);obj.pin_source(leaf)
        self.assertEqual([p['ancestor'] for p in obj.pins],[True]*4+[False]);obj.revalidate()
        # A declared code directory refuses add-file even when only an ancestor.
        v=volume();v.entries[leaf]['acl']=list(trusted);obj=v.install(sid)
        obj.declare_code_directories([driver])
        with self.assertRaises(a.Hold):obj.pin_source(leaf)
        self.assertFalse(obj.pins[-1]['ancestor'])
        # Declaration after the first pin is refused.
        v=volume();v.entries[leaf]['acl']=list(trusted);obj=v.install(sid);obj.pin_source(leaf)
        with self.assertRaises(a.Hold):obj.declare_code_directories([driver])
        # A directory that is itself the pinned target uses the full mask.
        v=volume();v.entry(driver,True)
        with self.assertRaises(a.Hold):v.install(sid).pin_source(driver)

    def test_embeddable_python_strict_inside_admission_root(self):
        import admin_entry
        tag='python%d%d'%sys.version_info[:2]
        class Strict(Pins):
            def __init__(self):self.strict=[]
            def pin_source(self,path):self.strict.append(str(path))
            def pin_readonly_source(self,*args):raise AssertionError('interpreter must not be tolerant')
        def build(root,pth=tag+'.zip\n.\n\n#import site\n',extra=None):
            directory=root/'python';directory.mkdir()
            files={'python.exe':b'inert interpreter',tag+'.dll':b'inert dll',tag+'.zip':b'inert zip',
                   '_ctypes.pyd':b'inert pyd'}
            if pth is not None:files[tag+'._pth']=pth.encode()
            for name,data in files.items():(directory/name).write_bytes(data)
            if extra:extra(directory)
            return directory/'python.exe'
        def tree_of(directory):
            # Independent restatement of the SPEC definition.
            names=sorted(path.name for path in directory.iterdir() if path.is_file())
            lines=[name+'\t'+a.sha((directory/name).read_bytes())+'\n' for name in names]
            return a.sha(''.join(lines).encode('utf-8'))
        def attempt(root,python,sha=None,admission_root=None,executable=None,tree=None,base=None,prefix=None):
            config=dict(admissionRoot=str(admission_root or root),
                        python=dict(path=str(python),sha256=sha or a.sha(b'inert interpreter'),
                                    treeSHA256=tree or tree_of(python.parent)))
            pins=Strict()
            with patch.object(admin_entry.sys,'executable',executable or str(python)),\
                 patch.object(admin_entry.sys,'_base_executable',base or executable or str(python),create=True),\
                 patch.object(admin_entry.sys,'prefix',prefix or str(python.parent)):
                return admin_entry.pinned_python(config,pins),pins
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);python=build(root)
            (path,record),pins=attempt(root,python)
            self.assertEqual(path,python)
            self.assertEqual(set(record['tree']),{'python.exe',tag+'.dll',tag+'.zip','_ctypes.pyd',tag+'._pth'})
            self.assertEqual(record['tree']['python.exe'],a.sha(b'inert interpreter'))
            self.assertEqual(record['treeSHA256'],tree_of(python.parent))
            self.assertEqual(admin_entry.python_tree_sha256(dict(b='2'*64,A='1'*64)),
                             a.sha(('A\t'+'1'*64+'\nb\t'+'2'*64+'\n').encode()))
            # Directory and every entry pinned strictly (pin_source), never tolerant.
            self.assertEqual(pins.strict[0],str(python.parent));self.assertEqual(len(pins.strict),6)
            for kwargs in (dict(sha='0'*64),dict(executable=r'C:\Python311\python.exe'),
                           dict(admission_root=str(root/'python'/'nested')),dict(tree='0'*64),
                           dict(base=r'C:\Python311\python.exe'),dict(prefix=str(root))):
                with self.assertRaises(a.Hold):attempt(root,python,**kwargs)
        refusals=[dict(pth=None),dict(pth='import site\n'),dict(pth=tag+'.zip\nLib\\site-packages\n'),
                  dict(extra=lambda d:(d/'Lib').mkdir()),dict(extra=lambda d:(d/'python39._pth').write_bytes(b'.\n')),
                  dict(extra=lambda d:(d/'pyvenv.cfg').write_bytes(b'home = elsewhere\n')),
                  dict(extra=lambda d:(d.parent/'pyvenv.cfg').write_bytes(b'home = elsewhere\n'))]
        for kwargs in refusals:
            with self.subTest(kwargs=kwargs),tempfile.TemporaryDirectory() as directory:
                root=pathlib.Path(directory);python=build(root,**kwargs)
                with self.assertRaises(a.Hold):attempt(root,python)
        # Any change to a file other than python.exe breaks the reviewed tree hash.
        for change in (lambda d:(d/'_ctypes.pyd').write_bytes(b'swapped pyd'),
                       lambda d:(d/'evil.pyd').write_bytes(b'planted'),
                       lambda d:(d/'_ctypes.pyd').unlink()):
            with tempfile.TemporaryDirectory() as directory:
                root=pathlib.Path(directory);python=build(root);reviewed=tree_of(python.parent)
                change(python.parent)
                with self.assertRaises(a.Hold):attempt(root,python,tree=reviewed)
        # An interpreter outside the admission root is refused before any pin.
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as other:
            python=build(pathlib.Path(other))
            with self.assertRaises(a.Hold):attempt(pathlib.Path(directory),python)
        source=__import__('inspect').getsource(admin_entry.run)
        for text in ("'admissionRoot'","'python'","declare_code_directories","pinned_python(config,admission)"):
            self.assertIn(text,source)
        self.assertNotIn('sys.executable,sha256',source);self.assertNotIn("'pythonSHA256',",source.split('fields(review')[0])
        review=source.split('fields(review')[1].split('Exact reviewed')[0]
        for text in ("'pythonTreeSHA256'","pythonTreeSHA256=config['python']['treeSHA256']","fresh-admin-review-v2"):
            self.assertIn(text,review)
        self.assertIn("('path','sha256','treeSHA256')",source)

    def test_tolerant_descriptor_change_refuses_revalidation(self):
        # An untrusted WRITE_DAC holder on a tolerant path can change the DACL:
        # revalidation then refuses (denial of service), never accepts a swap.
        sid=s.SID;data=b'interpreter image';volume=FakeVolume(PYTHON,data,self.sandbox_acl(sid))
        obj=volume.install(sid);obj.pin_readonly_source(PYTHON,a.sha(data),1024)
        handle=next(h for h,item in volume.handles.items() if item['id']==volume.entries[r'C:\Users\QA\AppData']['id'])
        volume.handles[handle]['acl']=volume.handles[handle]['acl']+[(0,0,0x40000,SANDBOX)]
        with self.assertRaises(a.Hold):obj.revalidate()

    def test_rpc_dangerous_fetch_before_close_or_spawn(self):
        for op in ('preflight','exit-supervisor'):
            with tempfile.TemporaryDirectory() as directory:
                root=pathlib.Path(directory);p=root/'request.json'
                p.write_bytes(a.encode(dict(nonce='a'*64,op=op)))
                calls=[]
                obj=rpc.PSDirectRPC(root/'inert.ps1','a'*64,popen=lambda *x,**k:calls.append('spawn'),
                                    child_environment=lambda x:{'PSModulePath':'inert'})
                obj.pending=(str(p.resolve()),a.sha(p.read_bytes()))
                obj.requests[str(p.resolve())]=obj.pending[1]
                obj.active={'transport':SimpleNamespace(close=lambda:calls.append('close'))}
                with self.assertRaises(rpc.Hold):obj('fetch',p)
                self.assertEqual(calls,[])

    def test_strict_bool_duplicate_and_request_binding(self):
        with self.assertRaises(a.Hold):a.decode(b'{"a":1,"a":2}')
        owner,_,_=self.owner()
        for field,value in [('sequence',True),('schema','old')]:
            req=a.decode(request(owner.bound,1,'inspect'));req[field]=value
            with self.assertRaises(a.Hold):owner.request(a.encode(req))

    def test_source_bootstrap_anchor_hash_and_preloaded_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);source=b'value = 37\n';name='fresh_admin_inert_fixture'
            (root/(name+'.py')).write_bytes(source)
            manifest=a.encode(dict(schema='fresh-admin-sources-v1',files={name+'.py':a.sha(source)}))
            finders=list(sys.meta_path)
            try:
                with self.assertRaises(a.Hold):bootstrap.load_pinned_modules(root,manifest,'f'*64,Pins(),[name])
                sys.modules[name]=SimpleNamespace(__file__=str(root/(name+'.py')))
                with self.assertRaises(a.Hold):bootstrap.load_pinned_modules(root,manifest,a.sha(manifest),Pins(),[name])
                del sys.modules[name]
                loaded=bootstrap.load_pinned_modules(root,manifest,a.sha(manifest),Pins(),[name])
                self.assertEqual(loaded[name].value,37)
                (root/(name+'.py')).write_bytes(b'value=0')
                with self.assertRaises(a.Hold):bootstrap.load_pinned_modules(root,manifest,a.sha(manifest),Pins(),[name])
            finally:
                sys.modules.pop(name,None)
                sys.meta_path[:]=finders

    def sandbox_acl(self,sid):
        # Observed read-only input chain: CodexSandboxUsers and an unresolved SID
        # hold inherited Modify (0x1301bf, includes DELETE) on folders and leaf.
        return [(0,0x13,0x1f01ff,n.SYSTEM),(0,0x13,0x1f01ff,n.ADMIN),(0,0x13,0x1f01ff,sid),
                (0,0x13,0x1301bf,SANDBOX),(0,0x13,0x1301bf,UNRESOLVED),(1,0x13,0x40000,'S-1-1-0')]

    def test_readonly_pin_tolerates_untrusted_writers_with_bound_hash(self):
        sid=s.SID;data=b'interpreter image';volume=FakeVolume(PYTHON,data,self.sandbox_acl(sid))
        obj=volume.install(sid)
        raw,evidence=obj.pin_readonly_source(PYTHON,a.sha(data),1024)
        self.assertEqual(raw,data);self.assertEqual(evidence['sha256'],a.sha(data))
        paths=[item['path'] for item in evidence['components']]
        self.assertEqual(paths[0],'C:\\');self.assertEqual(paths[-1],PYTHON)
        for item in evidence['components']:
            self.assertEqual(item['untrustedWriters'],[
                dict(sid=SANDBOX,mask='0x001301bf',flags='0x13'),
                dict(sid=UNRESOLVED,mask='0x001301bf',flags='0x13')])
        self.assertTrue(all(pin['tolerant'] for pin in obj.pins))
        obj.revalidate()
        # Strict mode (private root parents, manifests, config) still refuses it.
        with self.assertRaises(a.Hold):volume.install(sid).pin_source(PYTHON)
        with self.assertRaises(a.Hold):
            n.validate_acl(sid,False,self.sandbox_acl(sid),sid,False)
        with self.assertRaises(a.Hold):
            n.validate_acl(sid,True,self.sandbox_acl(sid),sid,True,True)

    def test_readonly_pin_refusals(self):
        sid=s.SID;data=b'interpreter image';digest=a.sha(data)
        def attempt(prepare,expected=digest):
            volume=FakeVolume(PYTHON,data,self.sandbox_acl(sid));obj=volume.install(sid)
            prepare(volume,obj)
            with self.assertRaises(a.Hold):obj.pin_readonly_source(PYTHON,expected,1024)
            return obj
        attempt(lambda v,o:None,'0'*64)
        attempt(lambda v,o:None,'not-a-digest')
        def hardlink(v,o):v.entries[PYTHON]['links']=2
        def reparse(v,o):v.entry(r'C:\Users\QA\AppData',True)['attributes']=0x410
        def unsupported(v,o):v.entries[PYTHON]['acl'].append((5,0,0x1,'S-1-1-0'))
        def owner(v,o):o._acl=lambda handle:('S-1-1-0',False,[],b'x')
        for prepare in (hardlink,reparse,unsupported,owner):attempt(prepare)
        with self.assertRaises(a.Hold):
            FakeVolume(PYTHON,data,self.sandbox_acl(sid)).install(sid).pin_readonly_source(PYTHON,digest,4)
        # File ID rebound by name between pin and revalidation.
        def rebind(v,o):
            def swap():v.entry(PYTHON,False,data)
            v.on_read=swap
        attempt(rebind)
        # Ancestor rename and rebind after a successful pin.
        volume=FakeVolume(PYTHON,data,self.sandbox_acl(sid));obj=volume.install(sid)
        obj.pin_readonly_source(PYTHON,digest,1024)
        volume.entry(r'C:\Users\QA\AppData\Local',True)
        with self.assertRaises(a.Hold):obj.revalidate()

    def test_system_executable_hardlink_exception(self):
        sid=s.SID;exe=r'C:\Windows\System32\OpenSSH\ssh.exe';data=b'inert ssh image';digest=a.sha(data)
        strict=[(0,0x13,0x1f01ff,n.SYSTEM),(0,0x13,0x1f01ff,n.ADMIN),(0,0x13,0x1200a9,'S-1-5-32-545')]
        def volume(owner,links=2):
            v=FakeVolume(exe,data,strict);v.entries[exe]['links']=links;v.entries[exe]['owner']=owner;return v
        for owner in (n.TI,n.SYSTEM,n.ADMIN):
            obj=volume(owner).install(sid)
            raw,evidence=obj.pin_system_executable(exe,digest,1024)
            self.assertEqual(raw,data)
            leaf=obj.pins[-1];self.assertEqual(leaf['path'],exe);self.assertFalse(leaf['tolerant'])
            # Evidence is recorded like read-only pins: links, owner, file ID, hash.
            self.assertEqual({k:evidence[k] for k in ('path','sha256','links','owner')},
                             dict(path=exe,sha256=digest,links=2,owner=owner))
            self.assertEqual(evidence['fileId'],'%08x:%08x%08x'%leaf['identity'])
            self.assertEqual([c['path'] for c in evidence['components']][-2:],[r'C:\Windows\System32\OpenSSH',exe])
            self.assertTrue(all(c['untrustedWriters']==[] for c in evidence['components']))
            # The executable's own directory is a code directory (full mask).
            self.assertFalse(obj.pins[-2]['ancestor']);self.assertTrue(obj.pins[-3]['ancestor'])
            obj.revalidate()
        # Add-file for an untrusted principal on the executable's directory refuses.
        v=volume(n.TI);v.entry(r'C:\Windows\System32\OpenSSH',True)['acl'].append((0,0,0x2,'S-1-5-11'))
        with self.assertRaises(a.Hold):v.install(sid).pin_system_executable(exe,digest,1024)
        v=volume(n.TI);v.entry(r'C:\Windows',True)['acl'].append((0,0,0x2,'S-1-5-11'))
        v.install(sid).pin_system_executable(exe,digest,1024)
        # links=2 with a user-owned leaf is refused.
        with self.assertRaises(a.Hold):volume(sid).install(sid).pin_system_executable(exe,digest,1024)
        # links=2, system owner, hash mismatch is refused.
        with self.assertRaises(a.Hold):volume(n.TI).install(sid).pin_system_executable(exe,'0'*64,1024)
        # Ordinary strict and read-only sources keep links==1 even when system-owned.
        with self.assertRaises(a.Hold):volume(n.TI).install(sid).pin_source(exe)
        with self.assertRaises(a.Hold):volume(n.TI).install(sid).pin_readonly_source(exe,digest,1024)
        # ACL rules are not relaxed: untrusted mutation ACE still refuses.
        v=volume(n.TI);v.entries[exe]['acl'].append((0,0,0x40000,'S-1-1-0'))
        with self.assertRaises(a.Hold):v.install(sid).pin_system_executable(exe,digest,1024)
        # Pure decision.
        n.validate_links(1,sid);n.validate_links(2,n.TI,True)
        for links,owner,flag in ((2,n.TI,False),(2,sid,True),(0,n.SYSTEM,False)):
            with self.assertRaises(a.Hold):n.validate_links(links,owner,flag)

    def test_ssh_inputs_bound_hashes_match_mismatch_missing(self):
        known=b'inert-host ssh-ed25519 KNOWNHOSTBYTES\n';client=b'INERT-PRIVATE-KEY-BYTES\n'
        good=dict(knownHostsSHA256=a.sha(known),clientSHA256=a.sha(client))
        with tempfile.TemporaryDirectory() as directory:
            key=pathlib.Path(directory)
            (key/'known_hosts2').write_bytes(known);(key/'client2').write_bytes(client)
            owner,_,_=self.owner();owner.resources['sshInputs']=dict(good)
            a.pin_ssh_inputs(owner,key)
            record=owner.journal.values['readonly-ssh-pins.json']
            self.assertEqual([x['sha256'] for x in a.decode(record)['sources']],[good['knownHostsSHA256'],good['clientSHA256']])
            for secret in (b'KNOWNHOSTBYTES',b'PRIVATE-KEY',a.encode(client.decode())[1:-1]):
                self.assertNotIn(secret,record)
            for field in good:
                owner,_,_=self.owner();owner.resources['sshInputs']=dict(good,**{field:'0'*64})
                with self.assertRaises(a.Hold):a.pin_ssh_inputs(owner,key)
                self.assertNotIn('readonly-ssh-pins.json',owner.journal.values)
                missing=dict(good);del missing[field]
                for value in (missing,dict(good,**{field:'A'*64}),dict(good,**{field:None}),dict(good,extra='0'*64)):
                    with self.assertRaises(a.Hold):a.ssh_input_hashes(value)
                    owner,_,_=self.owner();owner.resources['sshInputs']=value
                    with self.assertRaises(a.Hold):a.pin_ssh_inputs(owner,key)
            owner,_,_=self.owner()
            with self.assertRaises(KeyError):a.pin_ssh_inputs(owner,key)
        import admin_entry,inspect
        source=inspect.getsource(admin_entry.run)
        self.assertIn("'sshInputs'",source);self.assertIn("ssh_input_hashes(config['sshInputs'])",source)

    def test_native_pin_reparse_refusal_before_descriptor(self):
        # Native boundary replaced before construction; no DLL/API invocation.
        obj=n.WindowsAdmission.__new__(n.WindowsAdmission);obj.pins=[]
        calls=[]
        def info(handle,pointer):pointer._obj.attributes=0x410;return True
        obj.k=SimpleNamespace(CreateFileW=lambda *args:123,GetFileInformationByHandle=info)
        obj._descriptor=lambda *args:calls.append('descriptor')
        with self.assertRaises(a.Hold):obj._pin('INERT',True)
        self.assertEqual(calls,[])
        self.assertEqual(obj.pins[0]['handle'],123)

    def test_resident_bridge_timeout_late_collection_no_second_submission(self):
        owner,_,_=self.owner();now=[0.];spawns=[]
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);owner.journal.root=root
            class Admission(Pins):
                def create_root(self,path):path.mkdir();return path
            owner.journal.admission=Admission()
            process=SimpleNamespace(pid=777,poll=lambda:None)
            def popen(args,**kwargs):
                spawns.append(args)
                self.assertEqual(kwargs['env'],{'PSModulePath':'INERT'})
                (root/'guest-control/resident-ready.json').write_bytes(a.encode(dict(
                    schema='fresh-resident-ready-v1',nonce=owner.bound['nonce'],configSHA256=owner.bound['configSHA256'])))
                return process
            def pause(seconds):now[0]+=seconds
            bridge=ResidentRPC(owner,root,popen=popen,identity=lambda p:SimpleNamespace(creation=123,exe=sys.executable),clock=lambda:now[0],pause=pause,
                               environment=lambda exe:{'PSModulePath':'INERT'})
            path=root/'original-command.json';raw=a.encode(dict(nonce=owner.bound['nonce'],op='sample'));path.write_bytes(raw)
            with self.assertRaises(a.Hold):bridge.submit('submit','sample',path,raw,seconds=.1)
            with self.assertRaises(a.Hold):bridge.submit('submit','sample',path,raw,seconds=.1)
            self.assertEqual(bridge.sequence,1)
            (bridge.root/'resident-response-00000000000000000001.json').write_bytes(a.encode(dict(
                schema='fresh-resident-response-v1',nonce=owner.bound['nonce'],configSHA256=owner.bound['configSHA256'],
                sequence=1,requestSHA256=a.sha(raw),state='Collected',output='b3JpZ2luYWw=',error=None)))
            self.assertEqual(bridge.collect(.1),b'original')
            self.assertEqual(len(spawns),1)
            self.assertEqual(len(list(bridge.root.glob('resident-request-*.json'))),1)

    def test_resident_failed_operation_carries_bounded_diagnostic(self):
        owner,_,_=self.owner()
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);owner.journal.root=root
            class Admission(Pins):
                def create_root(self,path):path.mkdir();return path
            owner.journal.admission=Admission()
            def popen(args,**kwargs):
                (root/'guest-control/resident-ready.json').write_bytes(a.encode(dict(
                    schema='fresh-resident-ready-v1',nonce=owner.bound['nonce'],configSHA256=owner.bound['configSHA256'])))
                return SimpleNamespace(pid=778,poll=lambda:None)
            bridge=ResidentRPC(owner,root,popen=popen,identity=lambda p:SimpleNamespace(creation=124,exe=sys.executable),
                               clock=lambda:0.,pause=lambda s:None,environment=lambda exe:{'PSModulePath':'INERT'})
            path=root/'seal.json';raw=a.encode(dict(nonce=owner.bound['nonce'],op='seal-no-launch'));path.write_bytes(raw)
            bridge.pending=dict(nonce=owner.bound['nonce'],configSHA256=owner.bound['configSHA256'],sequence=1,requestSHA256=a.sha(raw))
            text='PropertyNotFoundException: no Name'+chr(13)+chr(10)+' @ owner-mailbox.ps1:190'+'x'*900
            (bridge.root/'resident-response-00000000000000000001.json').write_bytes(a.encode(dict(
                schema='fresh-resident-response-v1',nonce=owner.bound['nonce'],configSHA256=owner.bound['configSHA256'],
                sequence=1,requestSHA256=a.sha(raw),state='Failed',output=None,error=text)))
            with self.assertRaises(a.Hold) as caught:bridge.collect(.1)
            message=str(caught.exception)
            self.assertIn('owner-mailbox.ps1:190',message);self.assertNotIn(chr(13),message)
            self.assertLess(len(message),700)
            self.assertIsNone(bridge.pending)
            # A Collected response must not carry diagnostic text.
            bridge.pending=dict(nonce=owner.bound['nonce'],configSHA256=owner.bound['configSHA256'],sequence=2,requestSHA256=a.sha(raw))
            (bridge.root/'resident-response-00000000000000000002.json').write_bytes(a.encode(dict(
                schema='fresh-resident-response-v1',nonce=owner.bound['nonce'],configSHA256=owner.bound['configSHA256'],
                sequence=2,requestSHA256=a.sha(raw),state='Collected',output='',error='unexpected')))
            with self.assertRaises(a.Hold):bridge.collect(.1)

    def test_unresolved_observation_response_includes_reason_text(self):
        owner,_,_=self.owner();owner.fail(RuntimeError('original'))
        def collect(resources):raise a.Hold('Original resident operation failed: detail'+chr(10)+'y'*900)
        result=a.decode(owner.request(request(owner.bound,1,'collect-original'),collect=collect))['result']
        self.assertEqual(result['observation'],'unresolved');self.assertEqual(result['error'],'Hold')
        self.assertTrue(result['reason'].startswith('Original resident operation failed: detail '))
        self.assertEqual(len(result['reason']),512)


    def test_every_local_child_image_is_absolute(self):
        """No local child is started by a bare name (elevated PATH/cwd lookup)."""
        import ast,re
        runtime=pathlib.Path(__file__).resolve().parents[1]
        def absolute(value):
            return pathlib.PureWindowsPath(value).is_absolute() and not value.startswith(('\\','/'))
        bare=re.compile(r'(?i)^(ssh|scp|git|go|python3?|py|pythonw|powershell|pwsh|cmd|icacls|netsh|rasdial|'
                        r'sc|schtasks|reg|whoami|takeown|robocopy|certutil|wsl|tar|curl|nft)(\.exe)?$')
        spawners={'run','Popen','check_output','check_call','call','popen','runner','spawn_owned','observe'}
        offenders=[]
        for path in sorted(runtime.glob('*/*.py')):
            if path.name.startswith('test_'):continue
            tree=ast.parse(path.read_bytes(),filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node,ast.List) and node.elts and isinstance(node.elts[0],ast.Constant) \
                        and isinstance(node.elts[0].value,str) and bare.match(node.elts[0].value):
                    offenders.append('%s:%d %r'%(path.name,node.lineno,node.elts[0].value))
                if isinstance(node,ast.Call):
                    name=node.func.attr if isinstance(node.func,ast.Attribute) else getattr(node.func,'id',None)
                    if name in spawners and node.args and isinstance(node.args[0],ast.List) and node.args[0].elts:
                        first=node.args[0].elts[0]
                        if isinstance(first,ast.Constant) and not (isinstance(first.value,str) and absolute(first.value)):
                            offenders.append('%s:%d argv[0]=%r'%(path.name,node.lineno,first.value))
            source=path.read_text(encoding='utf-8')
            if "environ.get('SystemRoot'" in source or 'environ.get("SystemRoot"' in source:
                offenders.append(path.name+': SystemRoot-derived image path')
        # PowerShell: every native command name must carry a rooted path.
        scan=(r"$ErrorActionPreference='Stop';$seen=@{};"
              r"Get-ChildItem -LiteralPath $root -Recurse -Filter *.ps1 | ForEach-Object {"
              r" $t=$null;$e=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$t,[ref]$e);"
              r" foreach($c in $ast.FindAll({param($x)$x -is [System.Management.Automation.Language.CommandAst]},$true)){"
              r"  $n=$c.GetCommandName();$file=$_.Name;$line=$c.Extent.StartLineNumber;"
              r"  if($n -and $n -notmatch '[\\/]'){"
              r"   if(!$seen.ContainsKey($n)){$seen[$n]=[bool](Get-Command -Name $n -CommandType Application -ErrorAction SilentlyContinue)};"
              r"   if($seen[$n] -or $n -match '\.exe$'){'{0}:{1} {2}' -f $file,$line,$n}}"
              r"  if($n -eq 'Start-Process' -and $c.CommandElements.Count -gt 1){$a=$c.CommandElements[1];"
              r"   if($a -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $a.Value -notmatch '^[A-Za-z]:[\\/]'){'{0}:{1} Start-Process {2}' -f $file,$line,$a.Value}}}}")
        completed=subprocess.run([r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','-NoProfile',
            '-NonInteractive','-Command','& {param($root)'+scan+"} '"+str(runtime).replace("'","''")+"'"],stdin=subprocess.DEVNULL,
            capture_output=True,timeout=120,env=__import__('windows_powershell').environment())
        self.assertEqual(completed.returncode,0,completed.stderr.decode(errors='replace'))
        offenders+=[line for line in completed.stdout.decode(errors='replace').splitlines() if line.strip()]
        self.assertEqual(offenders,[])
        # Positive control: the scanner still sees a bare name.
        self.assertTrue(bare.match('ssh') and bare.match('Git.exe') and not bare.match('sshExecutable'))

    def test_live_ssh_requires_absolute_image(self):
        import live_prepare
        self.assertEqual(live_prepare.ssh_command('hostname',r'C:\Windows\System32\OpenSSH\ssh.exe')[:3],
                         [r'C:\Windows\System32\OpenSSH\ssh.exe','-F','none'])
        for value in ('ssh','ssh.exe',r'.\ssh.exe',r'\ssh.exe',r'\\server\share\ssh.exe','OpenSSH/ssh.exe'):
            with self.subTest(value=value),self.assertRaises(rpc.Hold):live_prepare.ssh_command('hostname',value)


# Child for the fresh-interpreter bootstrap closure: the same trust-root
# imports and load_pinned_modules call admin_entry.run performs before
# create_root. Only native admission is faked; nothing else is preloaded.
_FRESH_BOOTSTRAP_CHILD=r"""
import sys
driver,probe=sys.argv[1],sys.argv[2]
sys.path.insert(0,driver)
for name in ('copy','xml','admin_evidence','protected_evidence'):
    assert name not in sys.modules,'preloaded: '+name
import hashlib,pathlib
import admin_entry,admin_recovery,admin_native,admin_bootstrap
root=pathlib.Path(driver)
files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('*.py')
       if not p.name.startswith('test_')}
manifest=admin_recovery.encode(dict(schema='fresh-admin-sources-v1',files=files))
for name in ('admin_entry','admin_recovery','admin_native','admin_bootstrap'):
    sys.modules[name].__admin_source_sha256__=files[name+'.py']
class Admission:
    def pin_source(self,path):pass
    def revalidate(self):pass
names=['admin_containment','admin_processes','admin_transport','resident_rpc','admin_evidence',
       'admin_handoff','preparation_entry','admin_collect','process_handles']
modules=admin_bootstrap.load_pinned_modules(root,manifest,admin_recovery.sha(manifest),Admission(),names)
assert all(modules[name].__admin_source_sha256__==files[name+'.py'] for name in names)
# Optional-dependency probe (copy.py's org.python.core) is an ordinary miss.
try:import org.python.core
except ImportError as error:assert type(error) is ModuleNotFoundError,error
else:raise AssertionError('org.python.core resolved')
# A non-stdlib module outside the closure that IS on sys.path is not loaded.
sys.path.insert(0,probe)
try:import fresh_unpinned_probe
except ModuleNotFoundError as error:
    assert 'outside pinned' in str(error) and error.name=='fresh_unpinned_probe',error
else:raise AssertionError('unpinned module resolved from sys.path')
assert 'fresh_unpinned_probe' not in sys.modules
print('FRESH-BOOTSTRAP-OK')
"""


class FreshBootstrapClosureTests(unittest.TestCase):
    """Live Stage 2 regression: stdlib optional imports inside the pinned closure."""

    def interpreters(self):
        result=[sys.executable]
        embeddable=os.environ.get('BIMERON_TEST_EMBEDDABLE_PYTHON')
        if embeddable:result.append(embeddable)
        return result

    def test_fresh_isolated_bootstrap_closure_imports(self):
        driver=pathlib.Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory)/'fresh_unpinned_probe.py').write_bytes(b'raise SystemExit(99)\n')
            for interpreter in self.interpreters():
                with self.subTest(interpreter=interpreter):
                    flags=['-I','-S','-B',*(['-O'] if sys.flags.optimize else [])]
                    completed=subprocess.run([interpreter,*flags,'-c',_FRESH_BOOTSTRAP_CHILD,str(driver),directory],
                        cwd=directory,stdin=subprocess.DEVNULL,capture_output=True,timeout=120)
                    output=(completed.stdout+completed.stderr).decode(errors='replace')
                    self.assertEqual(completed.returncode,0,output)
                    self.assertIn('FRESH-BOOTSTRAP-OK',output)

    def test_missing_non_stdlib_import_fails_closed_in_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);source=b'value = 5\n';name='fresh_admin_closure_fixture'
            (root/(name+'.py')).write_bytes(source)
            (root/'fresh_admin_unpinned_fixture.py').write_bytes(b'raise SystemExit(99)\n')
            manifest=a.encode(dict(schema='fresh-admin-sources-v1',files={name+'.py':a.sha(source)}))
            finders=list(sys.meta_path);path=list(sys.path)
            try:
                sys.path.insert(0,directory)
                bootstrap.load_pinned_modules(root,manifest,a.sha(manifest),Pins(),[name])
                with self.assertRaises(ModuleNotFoundError) as caught:
                    import fresh_admin_unpinned_fixture  # noqa: F401
                self.assertNotIsInstance(caught.exception,a.Hold)
                self.assertEqual(caught.exception.name,'fresh_admin_unpinned_fixture')
                self.assertNotIn('fresh_admin_unpinned_fixture',sys.modules)
                import json  # stdlib still resolves through the ordinary finders
            finally:
                sys.modules.pop(name,None);sys.modules.pop('fresh_admin_unpinned_fixture',None)
                sys.meta_path[:]=finders;sys.path[:]=path


LIVE_DRIVER='C:\\Lab\\admission-parent-private\\admission-774d219d9bad42bc94732eb8097b7cd4\\verified-package\\runtime\\driver'


def _long_paths_enabled():
    if os.name!='nt':return True
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\FileSystem') as key:
            return winreg.QueryValueEx(key,'LongPathsEnabled')[0]==1
    except OSError:
        return False


class PathBudgetTests(unittest.TestCase):
    """Live run 9de2f235: a 260-character publication temporary failed every tick."""

    NAME='administrative-watcher-closed.json'

    def run_root(self,base,length):
        # Pad one component so the old '<name>.<32 hex>.pending' temp is exactly 260.
        base=pathlib.Path(os.path.abspath(base))
        root=base/('r'*(length-len(str(base))-1))
        self.assertEqual(len(str(root)),length);root.mkdir()
        return root

    def test_old_temporary_reaches_260_new_short_publication_succeeds(self):
        import uuid,watcher_release,binding
        length=260-(1+len(self.NAME)+1+32+len('.pending'))
        self.assertEqual(length,184)
        with tempfile.TemporaryDirectory(prefix='pb-') as directory:
            root=self.run_root(directory,length);target=root/self.NAME
            old=target.with_name(target.name+'.'+uuid.uuid4().hex+'.pending')
            self.assertEqual(len(str(old)),260)
            if not _long_paths_enabled():
                with self.assertRaises(FileNotFoundError):old.open('xb')
            self.assertFalse(old.exists())
            watcher_release.publish(target,b'{"ack":1}')
            self.assertEqual(target.read_bytes(),b'{"ack":1}')
            with self.assertRaises(FileExistsError):watcher_release.publish(target,b'{"ack":2}')
            cancellation.publish_once(root/'administrative-watcher-request.json',{'v':1})
            cancellation.publish_once(root/'administrative-watcher-request.json',{'v':1})
            binding.publish_once(root/'administrative-watcher-context.json',b'{}')
            self.assertEqual(sorted(p.name for p in root.iterdir()),
                ['administrative-watcher-closed.json','administrative-watcher-context.json','administrative-watcher-request.json'])
            # The endpoint path used by the failed-run watcher ACK.
            import admin_watcher_endpoint
            self.assertIs(admin_watcher_endpoint.publish,watcher_release.publish)

    def test_publication_temporary_length_is_independent_of_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target=pathlib.Path(directory)/('x'*120+'.json')
            temporary,stream=a.short_temporary(target);stream.close()
            self.assertEqual(len(temporary.name),a.TEMPORARY_NAME_CHARS)
            self.assertRegex(temporary.name,r'^\.[0-9a-f]{8}\.tmp$');temporary.unlink()

    def test_over_budget_write_refuses_with_named_reason(self):
        import transport
        with tempfile.TemporaryDirectory() as directory:
            base=pathlib.Path(os.path.abspath(directory))
            long=base/('n'*(a.MAX_PATH_CHARS-len(str(base))))
            self.assertEqual(len(str(long)),a.MAX_PATH_CHARS+1)
            with self.assertRaisesRegex(a.Hold,'MAX_PATH budget'):a.require_path(long)
            with self.assertRaisesRegex(rpc.Hold,'MAX_PATH budget'):rpc.freeze(long,b'x')
            with self.assertRaisesRegex(transport.Uncertain,'MAX_PATH budget'):transport.retain(long,{})
            with self.assertRaisesRegex(ValueError,'MAX_PATH budget'):cancellation.publish_once(long,{})
            journal=a.Journal(base,Pins())
            with self.assertRaisesRegex(a.Hold,'MAX_PATH budget'):
                journal.write('j'*(a.MAX_PATH_CHARS-len(str(base))-5)+'.json',b'{}')

    def test_admission_path_budget_refuses_and_live_root_fits(self):
        nonce='ab'*32
        old=pathlib.PureWindowsPath(LIVE_DRIVER)/('capture-prep-'+nonce)
        self.assertEqual(len(str(old)),184)
        with self.assertRaisesRegex(a.Hold,'Run path budget exceeded'):a.require_run_path_budget(old)
        self.assertEqual(a.private_root_name(nonce),'cp-'+nonce[:16])
        with self.assertRaises(a.Hold):a.private_root_name('not-a-nonce')
        new=pathlib.PureWindowsPath(LIVE_DRIVER)/a.private_root_name(nonce)
        length=a.require_run_path_budget(new)
        self.assertLessEqual(length,a.MAX_PATH_CHARS)
        self.assertEqual((len(str(new)),length),(126,214))
        with self.assertRaisesRegex(a.Hold,'Run path budget exceeded'):
            a.require_run_path_budget(pathlib.PureWindowsPath('C:\\'+'d'*190))
        # The inventory covers the widest instances of the real naming templates.
        inventory=set(a.RUN_PATH_INVENTORY)
        self.assertIn(('watcher-query-%06d'%999999)+'/'+('transport-%03d-capture-status'%999)+'.observer-exit.json',inventory)
        self.assertIn(('original-transport-%06d'%999999)+'/'+('transport-%03d-original'%999)+'.observer-exit.json',inventory)
        self.assertIn('owner-transport/rpc-evidence/'+('%06d-%s'%(999999,'submit'))+'/transport-999-rpc.observer-exit.json',inventory)
        self.assertIn('independent-tick-errors.jsonl',inventory)
        # admin_entry.run refuses before the private root exists and binds the nonce.
        import admin_entry,inspect
        source=inspect.getsource(admin_entry.run)
        self.assertNotIn("'capture-prep-'",source)
        order=[source.index(x) for x in ('root=driver/private_root_name(nonce)','require_run_path_budget(root)',
            'root=admission.create_root(root)',"journal.write('run-identity.json'",'Containment(root')]
        self.assertEqual(order,sorted(order))

    def test_tick_journal_records_every_refusal_bounded(self):
        import watcher_query
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            journal=watcher_query.TickJournal(root,limit=3,clock=lambda:1.0)
            journal.refuse(1,'administrative',FileNotFoundError('first'))
            for tick in (2,3,4):journal.refuse(tick,'administrative',FileNotFoundError('first'))
            journal.refuse(5,'release-ack',OSError('second'))
            journal.refuse(6,'query',ValueError('third'))
            journal.refuse(7,'stop',ValueError('fourth'))
            lines=[a.decode(x.encode()) for x in (root/'independent-tick-errors.jsonl').read_text().splitlines()]
            self.assertEqual([(x['tick'],x['stage'],x['error'],x['repeatsOfPrevious']) for x in lines],
                [(1,'administrative','FileNotFoundError',0),(5,'release-ack','OSError',3),(6,'query','ValueError',0)])
            self.assertTrue(lines[-1]['limitReached']);self.assertEqual(journal.count,7)
            broken=watcher_query.TickJournal(root/'missing',limit=3)
            broken.refuse(1,'x',OSError('y'));self.assertEqual((broken.count,broken.writeErrors),(1,1))

    def test_watch_prep_journals_every_loop_refusal(self):
        import ast
        tree=ast.parse((pathlib.Path(__file__).resolve().parent/'watch-prep.py').read_text(encoding='utf-8'))
        loop=[n for n in ast.walk(tree) if isinstance(n,ast.While)][-1]
        handlers=[n for n in ast.walk(loop) if isinstance(n,ast.ExceptHandler)]
        self.assertGreaterEqual(len(handlers),7)
        for handler in handlers:
            calls={c.func.id for c in ast.walk(handler) if isinstance(c,ast.Call) and isinstance(c.func,ast.Name)}
            self.assertIn('refuse',calls,ast.unparse(handler)[:120])
        # Every sticky-failure assignment in the loop is paired with a journal
        # call in the same block or in its directly enclosing block.
        parent={child:node for node in ast.walk(loop) for child in ast.iter_child_nodes(node)}
        def journals(node):
            return any(isinstance(c,ast.Call) and isinstance(c.func,ast.Name) and c.func.id=='refuse'
                       for x in node.body for c in ast.walk(x))
        for node in ast.walk(loop):
            body=getattr(node,'body',None)
            if not isinstance(body,list) or node is loop:continue
            if any(isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='failure' for t in x.targets) for x in body):
                self.assertTrue(journals(node) or journals(parent[node]),ast.unparse(node)[:120])

    def test_watcher_query_unresolved_resolves_deterministically(self):
        # (a) observation failed before any child existed: known no-dispatch.
        calls=[]
        with tempfile.TemporaryDirectory() as directory:
            class NoChild:
                def __init__(self,root,*args,**kwargs):self.children=[];self.closed=0
                def observe(self,*args,**kwargs):calls.append('a');raise FileNotFoundError('intent unwritable')
                def close(self):self.closed+=1
            query=Query(directory,['inert'],transport=NoChild)
            with self.assertRaises(FileNotFoundError):query()
            self.assertIsNotNone(query.active);self.assertIsNone(query.unresolved())
            with self.assertRaisesRegex(a.Hold,'not-dispatched'):query()
            self.assertIsNone(query.active);self.assertEqual(query.entries[0]['resolution'],'not-dispatched')
            self.assertEqual(query.entries[0]['transport'].closed,1)
            with self.assertRaises(FileNotFoundError):query()
            self.assertEqual(calls,['a','a'])
        # (b) child started, identity/handle read failed: owned until the same Popen exits.
        status=[None];calls=[]
        with tempfile.TemporaryDirectory() as directory:
            class NoIdentity:
                def __init__(self,root,*args,**kwargs):self.root=root;self.children=[]
                def observe(self,*args,**kwargs):
                    calls.append('b')
                    self.children.append(dict(process=SimpleNamespace(poll=lambda:status[0]),handle=None,
                        record=dict(identity=None,files={'stdout':str(self.root/'never-read')})))
                    raise OSError('identity read failed')
                def close(self):calls.append('close')
            query=Query(directory,['inert'],transport=NoIdentity)
            with self.assertRaises(OSError):query()
            self.assertIs(query.unresolved(),query.active)
            with self.assertRaisesRegex(a.Hold,'still outstanding'):query()
            self.assertIsNotNone(query.active);status[0]=0
            self.assertIsNone(query.unresolved())
            with self.assertRaisesRegex(a.Hold,'terminal-unauthenticated; no output'):query()
            self.assertIsNone(query.active);self.assertIsNone(query.unresolved())
            self.assertEqual(calls,['b','close'])
        # (c) the transport itself could not be constructed.
        with tempfile.TemporaryDirectory() as directory:
            def broken(*args,**kwargs):raise OSError('no transport')
            query=Query(directory,['inert'],transport=broken)
            with self.assertRaises(OSError):query()
            self.assertIsNone(query.unresolved())
            with self.assertRaisesRegex(a.Hold,'not-dispatched'):query()
            self.assertIsNone(query.active)

RUNTIME=pathlib.Path(__file__).resolve().parents[1]
# Only the held-run disposition tool reads legacy evidence under the old name.
LEGACY_ROOT_NAME_ALLOWLIST={'host/dispose-held-run.py'}


class PrivateRootNameTests(unittest.TestCase):
    """Runtime paths use the admitted private run root, never a name template."""

    def test_no_runtime_code_builds_legacy_root_paths(self):
        offenders=[]
        for path in sorted(RUNTIME.rglob('*')):
            if path.suffix not in ('.py','.ps1') or not path.is_file():continue
            if path.name.startswith(('test_','test-')):continue
            relative=path.relative_to(RUNTIME).as_posix()
            if 'capture-prep-' in path.read_text(encoding='utf-8',errors='replace') and relative not in LEGACY_ROOT_NAME_ALLOWLIST:
                offenders.append(relative)
        self.assertEqual(offenders,[])
        # The allowlisted reader still exists and is the only legacy reader.
        for relative in LEGACY_ROOT_NAME_ALLOWLIST:
            self.assertIn('capture-prep-',(RUNTIME/relative).read_text(encoding='utf-8'))

    def test_controller_launches_pass_admitted_root(self):
        source=(RUNTIME/'driver/preparation_body.py').read_text(encoding='utf-8')
        self.assertIn("'-File',str(HERE/'guest-read.ps1'),'-Mode',mode,'-Nonce',nonce,'-ControlPath',str(out)]",source)
        self.assertIn("'-File',str(HERE/'prepare-task.ps1'),'-Nonce',nonce,'-ControlPath',str(out)",source)
        self.assertIn('out=administrative_owner.journal.root',source)

    def test_bound_private_root_and_python_callers(self):
        nonce='ab'*32
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)/a.private_root_name(nonce);root.mkdir()
            with self.assertRaises(FileNotFoundError):a.bound_private_root(root,nonce)
            (root/'run-identity.json').write_bytes(a.encode(dict(schema='fresh-admin-run-identity-v1',nonce=nonce,rootName=root.name)))
            self.assertEqual(a.bound_private_root(root,nonce),root)
            with self.assertRaisesRegex(a.Hold,'Private run identity binding'):a.bound_private_root(root,'cd'*32)
            other=pathlib.Path(directory)/('cp-'+'0'*16);other.mkdir()
            (other/'run-identity.json').write_bytes((root/'run-identity.json').read_bytes())
            with self.assertRaisesRegex(a.Hold,'Private run identity binding'):a.bound_private_root(other,nonce)
        import live_prepare
        with self.assertRaisesRegex(rpc.Hold,'Admitted private run root required'):
            live_prepare.prepare_live(dict(SHA256='a'*64,Nonce=nonce,PolicySHA256='b'*64),
                                      nonce,{},ssh=r'C:\Windows\System32\OpenSSH\ssh.exe',out=None,
                                      config_path=pathlib.Path('absent'),runner=lambda *x,**y:self.fail('no runner'))

    @unittest.skipUnless(os.name=='nt','Windows PowerShell hermetic harness')
    def test_driver_scripts_with_cp_root_hermetic(self):
        import windows_powershell
        with tempfile.TemporaryDirectory() as work:
            completed=subprocess.run([str(windows_powershell.executable()),'-NoProfile','-NonInteractive',
                '-ExecutionPolicy','Bypass','-File',str(RUNTIME/'driver/test-private-root.ps1'),
                '-Driver',str(RUNTIME/'driver'),'-Work',work],stdin=subprocess.DEVNULL,
                capture_output=True,timeout=120,env=windows_powershell.environment())
        output=completed.stdout.decode(errors='replace')
        self.assertEqual(completed.returncode,0,output+completed.stderr.decode(errors='replace'))
        self.assertEqual([line for line in output.splitlines() if line.startswith('PASS ')],
            ['PASS restore-permit','PASS stop','PASS persistent','PASS guest-read refusals','PASS prepare-task'])

class AtomicPublicationTests(unittest.TestCase):
    """Live run 7a85aad9: a poller read resident-ready.json created but not yet written."""
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.directory.name)
        b,r,_,_=fixture();self.owner=a.Owner(b,Journal(),r,e.validate_phase1,e.validate_phase2)
        self.owner.journal.root=self.root
        class Admission(Pins):
            def create_root(self,path):path.mkdir();return path
        self.owner.journal.admission=Admission()
        self.ready=a.encode(dict(schema='fresh-resident-ready-v1',nonce=self.owner.bound['nonce'],
                                 configSHA256=self.owner.bound['configSHA256']))

    def tearDown(self):self.directory.cleanup()

    def slow_writer(self,raw,delay=.3):
        """The old non-atomic writer: CreateNew an empty file, write the bytes later."""
        target=self.root/'guest-control/resident-ready.json';created=threading.Event()
        def run():
            with target.open('xb') as stream:
                stream.flush();created.set();time.sleep(delay)
                stream.write(raw);stream.flush()
        thread=threading.Thread(target=run);thread.start();created.wait(5)
        return target,thread

    def bridge(self,popen,clock=time.monotonic,pause=time.sleep):
        return ResidentRPC(self.owner,self.root,popen=popen,identity=lambda p:SimpleNamespace(creation=125,exe=sys.executable),
                           clock=clock,pause=pause,environment=lambda exe:{'PSModulePath':'INERT'})

    def test_old_reader_fails_new_reader_waits_for_complete_file(self):
        threads=[]
        def popen(args,**kwargs):
            target,thread=self.slow_writer(self.ready);threads.append(thread)
            # The previous _wait returned the bytes of any present file at once.
            with self.assertRaises(ValueError):a.decode(target.read_bytes())
            return SimpleNamespace(pid=779,poll=lambda:None)
        bridge=self.bridge(popen)
        threads[0].join()
        self.assertEqual((bridge.root/'resident-ready.json').read_bytes(),self.ready)

    def test_complete_file_failing_validation_still_fails(self):
        wrong=a.encode(dict(schema='fresh-resident-ready-v1',nonce='0'*64,configSHA256=self.owner.bound['configSHA256']))
        threads=[]
        def popen(args,**kwargs):
            threads.append(self.slow_writer(wrong,.1)[1]);return SimpleNamespace(pid=780,poll=lambda:None)
        with self.assertRaisesRegex(a.Hold,'Resident readiness binding'):self.bridge(popen)
        threads[0].join()

    def test_partial_file_at_deadline_fails_and_empty_times_out(self):
        now=[0.]
        def pause(seconds):now[0]+=seconds
        def popen(args,**kwargs):
            (self.root/'guest-control/resident-ready.json').write_bytes(self.ready[:7])
            return SimpleNamespace(pid=781,poll=lambda:None)
        with self.assertRaisesRegex(a.Hold,'malformed at deadline'):self.bridge(popen,clock=lambda:now[0],pause=pause)
        bridge=ResidentRPC.__new__(ResidentRPC);bridge.owner=self.owner;bridge.root=self.root/'guest-control'
        bridge.clock=lambda:now[0];bridge.pause=pause;bridge.process=SimpleNamespace(poll=lambda:None)
        (bridge.root/'resident-closed.json').write_bytes(b'')
        with self.assertRaisesRegex(a.Hold,'Resident observation timeout'):bridge._wait('resident-closed.json',1)
        # Exit with only a partial publication is a failure, never a retry.
        bridge.process=SimpleNamespace(poll=lambda:0)
        with self.assertRaisesRegex(a.Hold,'exited with malformed publication'):bridge._wait('resident-ready.json',1)

    def test_publish_exclusive_idempotent_conflict_and_short_temporary(self):
        target=self.root/('resident-response-%020d.json'%1)
        seen=[]
        real=a.short_temporary
        def spy(path):
            temporary,stream=real(path);seen.append(temporary);return temporary,stream
        with patch.object(a,'short_temporary',spy):
            a.publish_exclusive(target,b'{"a":1}')
            a.publish_exclusive(target,b'{"a":1}')  # identical bytes: idempotent
            with self.assertRaisesRegex(a.Hold,'Publication conflict'):a.publish_exclusive(target,b'{"a":2}')
        self.assertEqual(target.read_bytes(),b'{"a":1}')
        self.assertEqual(len(seen),1)
        self.assertRegex(seen[0].name,r'^\.[0-9a-f]{8}\.tmp$')
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),[target.name])
        # A file appearing between the existence check and the link is compared, not replaced.
        other=self.root/'resident-closed.json'
        def racing(path):
            temporary,stream=real(path);other.write_bytes(b'{"b":0}');return temporary,stream
        with patch.object(a,'short_temporary',racing):
            with self.assertRaisesRegex(a.Hold,'Publication conflict'):a.publish_exclusive(other,b'{"b":1}')
        self.assertEqual(other.read_bytes(),b'{"b":0}')
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),sorted([target.name,other.name]))

    def test_journal_and_resident_publications_are_atomic(self):
        journal=a.Journal(self.root,Pins());calls=[]
        real=a.publish_exclusive
        with patch.object(a,'publish_exclusive',lambda *args:calls.append(args[0].name) or real(*args)):
            journal.write('administrative-watcher-request.json',b'{}')
        self.assertEqual(calls,['administrative-watcher-request.json'])
        with self.assertRaisesRegex(a.Hold,'Journal collision'):journal.write('administrative-watcher-request.json',b'{"x":1}')
        bridge=ResidentRPC.__new__(ResidentRPC);bridge.owner=self.owner;bridge.root=self.root
        bridge._publish('resident-close-request.json',b'{"c":1}');bridge._publish('resident-close-request.json',b'{"c":1}')
        with self.assertRaisesRegex(a.Hold,'Resident publication conflict'):bridge._publish('resident-close-request.json',b'{}')


if __name__=='__main__':unittest.main(verbosity=2)
