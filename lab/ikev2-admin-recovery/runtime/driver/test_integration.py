"""Local integration fixtures: real policy/capture bytes; no native/network execution."""
import copy, json, pathlib, tempfile, unittest, struct, socket
from types import SimpleNamespace
from protected_transport import Adapter, encode, sha, strict, freeze
from protected_stage import Stage
from protected_evidence import check_causal_admission, assess_causal_escape, check_exact_drain
from persistent import FirstFailure
from records import TARGETS
from test_policy_full300 import F, Policy
N='a'*64

def fixture():
    identity=dict(pid=12,start='2026-11-04T00:00:00Z',sid='S-1-5-21-1-2-3-1001')
    proc=dict(identity,path='C:\\Windows\\powershell.exe',sha256='b'*64,integrity='S-1-16-8192',elevated=False,alive=True,parent=11,arguments=['fixture'])
    parent=dict(proc,pid=11,path='C:\\Windows\\cmd.exe',parent=1)
    launch=dict(nonce=N,guid='original-instance',engine=11,bookmark=1)
    registration=dict(principal=dict(sid=identity['sid']))
    pin=dict(nonce=N,producer=identity,process=[proc,parent],launch=launch,event200=dict(engine=11,guid=launch['guid'],record=2),registration=registration,inputs=[dict(role='probe.ps1',sha256=sha((pathlib.Path(__file__).parent/'probe.ps1').read_bytes()))])
    rows=[];packets=[]
    def row(kind,target,status,rnd):
        rows.append(dict(nonce=N,sequence=len(rows)+1,round=rnd,producer=identity,utc='2026-11-04T00:00:00Z',ticks=len(rows)+1,kind=kind,target=target,status=status))
    row('start','all',json.dumps(dict(origin=1,frequency=1,seconds=900)),0)
    for target in sorted(TARGETS):
        if target.startswith('tcp/'):row('tcp-open',target,'connected',0)
    from preexisting import payload as exact_payload, EXACT
    sockets={}
    for port in (500,4500):
        target=f'carrier/<LAB_PUBLIC_IP>/{port}'
        sockets[target]=dict(id=N+'-'+str(port),handle=str(port),local=f'192.0.2.2:{port}',remote=f'<LAB_PUBLIC_IP>:{port}',family='InterNetwork',type='Dgram',protocol='Udp',exclusive=True,session=2)
        row('socket-open',target,'connected',0);rows[-1]['detail']=sockets[target]
    def round(rnd):
        row('round-start','all','begin',rnd)
        for target in sorted(TARGETS):
            kind,dst,port=target.split('/');port=int(port);src='fd42:8::2' if ':' in dst else '192.0.2.2';sport=port if kind=='carrier' else 10000+port
            row('attempt',target,'bind-and-send' if kind=='carrier' else 'preexisting-send' if kind=='tcp' else 'send',rnd)
            row('result',target,'sent local='+('['+src+']' if ':' in src else src)+':'+str(sport),rnd)
            payload=('STEP10-'+N+'-ROUND-'+str(rnd)+'-END').encode()
            if port==53:
                payload=bytes.fromhex('531001000001000000000000')
                for label in ('s10',N[:32],N[32:],'r'+str(rnd),'test'):
                    b=label.encode();payload+=bytes([len(b)])+b
                payload+=bytes.fromhex('0000010001')
                if kind=='tcp':payload=len(payload).to_bytes(2,'big')+payload
            if kind=='carrier':
                fence=next((r for r in rows if r['kind']=='post-arm-fence'),None)
                phase='POST' if fence else 'PRE';measurement=fence['detail']['measurementNonce'] if fence else '-'
                payload=exact_payload(N,phase,measurement,sockets[target]['id'],port,rnd)
                rows[-2]['status']='preexisting-connected-send'
                rows[-2]['detail']=dict(socket=sockets[target],phase=phase,measurementNonce=measurement)
                rows[-1]['status']=f'sent:{len(payload)} local={src}:{port}'
                rows[-1]['detail']=dict(rows[-2]['detail'],bytes=len(payload),socketError=0)
            proto=6 if kind=='tcp' else 17
            transport=struct.pack('!HH',sport,port)+(b'\0'*8+b'\x50\x18'+b'\0'*6 if proto==6 else struct.pack('!HH',8+len(payload),0))+payload
            if ':' in dst:
                ip=b'\x60\0\0\0'+struct.pack('!HBB',len(transport),proto,64)+socket.inet_pton(socket.AF_INET6,src)+socket.inet_pton(socket.AF_INET6,dst);eth=b'\0'*12+b'\x86\xdd'
            else:
                ip=b'\x45\0'+struct.pack('!H',20+len(transport))+b'\0'*5+bytes([proto])+b'\0'*2+socket.inet_aton(src)+socket.inet_aton(dst);eth=b'\0'*12+b'\x08\0'
            packet=eth+ip+transport;packets.append(struct.pack('<IIII',100+rnd,0,len(packet),len(packet))+packet)
        row('round-complete','all','complete',rnd)
    round(1);round(2);round(3)
    journal=lambda: b''.join(encode(r)+b'\n' for r in rows)
    pcap=lambda: struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+b''.join(packets)
    expected=dict(nonce=N,registration=registration,inputs=pin['inputs'],images=dict(powershell=proc,cmd=parent))
    files={'original-producer-pin.json':encode(pin),'expected.json':encode(expected)}
    for role in ('supervisor','collector','barrier'):
        files['reader-'+role+'-ready.json']=encode(dict(nonce=N,role=role,producer=identity,noHandle=False,ready='now',opened='earlier',failure=None))
    v=dict(exactPorts=[dict(address='192.0.2.2',port=p,pid=identity['pid']) for p in (500,4500)],nonce=N,pin=pin,files=files,clock=dict(utc=1793750401),readiness=dict(utc='2026-11-04T00:00:00Z',ready=True,healthy=True,failure=None),journal=journal(),pcap=pcap())
    return v,rows,round,journal,pcap

class Integration(unittest.TestCase):
    def test_final_file_acl_required(self):
        from protected_evidence import check_independent_absence
        once=b'offline-once'
        proof=encode(dict(schema='full300-no-launch-v1',nonce=N,supervisorOnceSHA256=sha(once),sealed=True,launchAttempted=False))
        baseline=dict(xml='task',sddl='api-acl',fileSddl='file-acl')
        task=dict(baseline,state=3,instanceGuids=[],instanceGuid='offline-instance')
        final=dict(nonce=N,proof=proof,once=once,
            exit_ready=encode(dict(nonce=N,proofSHA256=sha(proof),supervisorOnceSHA256=sha(once))),
            task_registration=encode(baseline),task_final=encode(task),
            task_instance=encode(dict(instanceGuid='offline-instance')),ras='No connections',bfe=b'<wfpstate/>')
        self.assertEqual(check_independent_absence(final,None,N)['status'],'PASS')
        for field,original in (('task_registration',baseline),('task_final',task)):
            for value in (None,'','changed'):
                with self.subTest(field=field,value=value):
                    mutated=dict(original)
                    if value is None: mutated.pop('fileSddl')
                    else: mutated['fileSddl']=value
                    self.assertEqual(check_independent_absence(dict(final,**{field:encode(mutated)}),None,N)['status'],'INCONCLUSIVE')

    def test_real_stage_to_c1_failure_cleanup(self):
        from protected_evidence import guid
        here=pathlib.Path(__file__).parent
        v,rows,add_round,journal,pcap=fixture()
        Policy.setUpClass()
        rules=encode(Policy.rules);xml=Policy.xml
        rule_values=strict(rules);owned=[guid(r['ID']) for r in rule_values if r['Name']=='STEP9 ABI LAB ONLY']
        guids=encode(['151aba0b-bb73-481c-98b9-61c901fa087e','221dd053-53bc-4930-b8bf-03a1922f2059']+owned)
        with tempfile.TemporaryDirectory() as temp:
            out=pathlib.Path(temp);calls=[];started=False;config=None;cleaned=False
            def rpc(mode,path):
                nonlocal started,config,cleaned
                c=strict(path.read_bytes());calls.append(c.get('op',mode))
                root=path.parent if mode=='preflight' else path.parent.parent
                if mode=='preflight':
                    config=c
                    freeze(root/'task-instance.json',encode(dict(instanceGuid='task-instance')))
                    return encode(dict(schema='full300-supervisor-once-v1',nonce=N,configSHA256=sha(path.read_bytes()),instanceId='instance',pid=99,creationFileTime='123',principalSid=c['principalSid'],sessionId=2,elevated=True))
                binding=dict(SHA256=config['ownerSHA256'],Nonce=N,PolicySHA256=sha((sha(rules)+'\n'+sha(guids)).encode()))
                if c['op']=='start':started=True
                if c['op']=='cleanup':cleaned=True
                files={'bfe-bootstrap.xml':xml,'rules-bootstrap.json':rules,'guids.json':guids,'gate-request.json':encode(binding),
                    'gate-status.json':encode(dict(binding,State='CLOSED' if cleaned else 'OBSERVING' if started else 'HOLD',Errors=[],Completed300=started,ElapsedNS=300000000000)),
                    'events.jsonl':encode(dict(Event='bootstrap HOLD'))+b'\n'+(encode(dict(Event='observation started'))+b'\n' if started else b'')+(encode(dict(Event='closed'))+b'\n' if cleaned else b'')}
                refs=[]
                if c['op']=='sample':
                    for name,b in files.items():
                        n=str(c['seq'])+'-'+name;freeze(root/'samples'/n,b);refs.append(dict(name=n,sha256=sha(b),length=len(b)))
                if cleaned and c['op']=='sample':
                    statusref=next(r for r in refs if r['name'].endswith('-gate-status.json'))
                    exitraw=encode(dict(schema='full300-owner-exit-v1',nonce=N,supervisorOnceSHA256=sha((root/'proofs/supervisor-once.json').read_bytes()),owner=dict(pid=42,creationFileTime='123',path='C:/BimeronFull300/'+N+'/full300-owner.exe',sha256=config['ownerSHA256']),waitResult='signalled',nativeStatus=statusref))
                    freeze(root/'proofs/owner-exit.json',exitraw);refs.append(dict(name='owner-exit.json',sha256=sha(exitraw),length=len(exitraw)))
                if c['op']=='exit-supervisor':
                    freeze(root/'task-registration.json',encode(dict(xml='task',sddl='acl',fileSddl='file-acl')))
                    freeze(root/'task-final.json',encode(dict(xml='task',sddl='acl',fileSddl='file-acl',state=3,instanceGuids=[],instanceGuid='task-instance')))
                    freeze(root/'proofs/supervisor-exit-ready.json',encode(dict(nonce=N,proofSHA256=c['body']['ownerExit']['sha256'],supervisorOnceSHA256=sha((root/'proofs/supervisor-once.json').read_bytes()))))
                return encode(dict(schema='full300-owner-response-v1' ,nonce=N,configSHA256=c['configSHA256'],seq=c['seq'],commandSHA256=sha(path.read_bytes()),outcome='accepted',state='OWNING',owner=dict(pid=42,creationFileTime='123',path='C:/BimeronFull300/'+N+'/full300-owner.exe',sha256=config['ownerSHA256'],handleState='live',exitCode=None),refs=refs,error=None))
            a=Adapter(here,out,N,FirstFailure(),rpc=rpc,collect=lambda capture:copy.deepcopy(v),principal=lambda:'S-1-5-21-1-2-3-1001',pause=lambda _:None)
            def publish(script,*args,**kwargs):
                path=pathlib.Path(args[args.index('-RequestPath')+1]);request=strict(path.read_bytes())
                if request['schema']=='c1pe-challenge-v1':
                    rows.append(dict(rows[-1],sequence=len(rows)+1,kind='post-arm-fence',target='all',status='consumed',ticks=rows[-1]['ticks']+1,
                        detail=dict(challengeSHA256=sha(path.read_bytes()),requestId=request['requestId'],measurementNonce=request['measurementNonce'],frequency=1,sockets=[r['detail'] for r in rows if r['kind']=='socket-open'])))
                    v['journal']=journal()
                return encode(dict(nonce=N,sha256=sha(path.read_bytes()),name=path.name))
            a._ps=publish
            stage=Stage(here,out,N,a.failure,adapter=a);stage.start();stage.thread.join(10)
            self.assertIsNone(stage.error,str(stage.error));self.assertTrue(stage.observationCompleted)
            self.assertEqual(stage.measurement['status'],'INCONCLUSIVE');self.assertNotIn('cleanup',calls)
            self.assertEqual(config['ownerSHA256'],sha(a.owner_path.read_bytes()))
            # Natural producer completion and every retained reader/inspector/task proof.
            from cancellation import freeze_controller_drain
            pin=v['pin'];files=v['files'];final=dict(nonce=N,exitVerified=True,taskClosureVerified=True,completed=True,requestId=None,processes=[dict(pid=x['pid'],start=x['start'],alive=False) for x in pin['process']])
            # Preserve original expected bytes.
            files['launch.json']=encode(pin['launch']);files['registration.json']=encode(pin['registration'])
            files['inspector-final.json']=encode(final)
            files['inspector-exit-proof.json']=encode(dict(schema='full300-inspector-exit-v1',nonce=N,inspector=dict(pid=91,creationFileTime='789',path='fixture',sha256='e'*64),exitCode=0,expectedSHA256=sha(files['expected.json']),waitResult='signalled',inspectorFinalSHA256=sha(files['inspector-final.json'])))
            local={};owners={}
            for role in ('supervisor','collector','barrier'):
                local[role]=dict(nonce=N,role=role,noHandle=False,opened='2026-11-04T00:00:00Z',closed='2026-11-04T00:15:01Z')
                files['reader-'+role+'-closed.json']=encode(local[role])
                owners[role]=SimpleNamespace(identity=dict(pid=123,startIdentityStatus='verified',startFiletime=456),poll=lambda:0,command=['fake',role])
            freeze_controller_drain(out,N,owners,local)
            v['task']=dict(schema='full300-task-readback-v1',nonce=N,path='\\BimeronStep8Probe',state=3,instanceGuids=[],lastTaskResult=0,launchInstanceGuid=pin['launch']['guid'])
            terminal={k:v for k,v in rows[-1].items() if k!='detail'}
            terminal.update(sequence=len(rows)+1,kind='measurement-end',status='complete',ticks=901)
            terminal_rows=[terminal]
            for opened in [r for r in rows if r['kind']=='socket-open']:
                terminal_rows.append(dict(terminal,sequence=len(rows)+len(terminal_rows)+1,kind='socket-close',target=opened['target'],status='disposed',detail=opened['detail']))
            terminal_rows.append(dict(terminal,sequence=len(rows)+len(terminal_rows)+1,kind='end'))
            v['journal']=journal()+b''.join(encode(r)+b'\n' for r in terminal_rows)
            v['bfe']=b'<wfpstate><providers/><subLayers/><layers/></wfpstate>';v['ras']='No connections'
            # U1 has no copied live configuration: exercise the original failure
            # cleanup route here; stock admission/finalization has separate mock tests.
            stage.executionFailure=RuntimeError('injected offline failure before stock admission')
            stage.before_restore()
            self.assertTrue(stage.restorationAllowed)
            self.assertEqual(calls.count('cleanup'),1)
            wrapper=strict(a.prelaunch_drain['wrapper'])
            for key in ('admissions','readerClosures','taskClosure','inspectorExit','inspectorFinal','producerPin','terminalJournal'):
                broken=copy.deepcopy(a.prelaunch_drain);name=wrapper[key]['name'];broken['files'][name]+=b'changed'
                self.assertNotEqual(check_exact_drain(broken,N)['status'],'PASS',key)
            # A hash-consistent cancelled terminal without its exact stop request
            # must not borrow a natural-completion closure.
            broken=copy.deepcopy(a.prelaunch_drain);drain=strict(broken['wrapper'])
            name=drain['terminalJournal']['name'];terminal_rows=[strict(x) for x in broken['files'][name].splitlines()]
            terminal_rows[-1].update(status='cancelled',requestId='f'*32)
            broken['files'][name]=b''.join(encode(r)+b'\n' for r in terminal_rows)
            ref=dict(name=name,sha256=sha(broken['files'][name]),length=len(broken['files'][name]))
            taskname=drain['taskClosure']['name'];taskclosure=strict(broken['files'][taskname]);taskclosure['terminalJournal']=ref
            broken['files'][taskname]=encode(taskclosure);drain['terminalJournal']=ref
            drain['taskClosure']=dict(name=taskname,sha256=sha(broken['files'][taskname]),length=len(broken['files'][taskname]))
            broken['wrapper']=encode(drain)
            self.assertNotEqual(check_exact_drain(broken,N)['status'],'PASS','Mismatched cancellation/closure')
    def test_preflight_refusal_before_supervisor_attempt(self):
        from cancellation import freeze_controller_drain
        from protected_evidence import check_independent_absence
        with tempfile.TemporaryDirectory() as temp:
            out=pathlib.Path(temp);nonce=N
            files={'expected.json':encode(dict(registration={'xml':'original'})),
                   'registration.json':encode({'xml':'original'}),
                   'inspector-final.json':encode(dict(nonce=N,launchNeverOccurred=True,launch=None,processes=[]))}
            files['inspector-exit-proof.json']=encode(dict(nonce=N,waitResult='signalled',inspectorFinalSHA256=sha(files['inspector-final.json']),expectedSHA256=sha(files['expected.json'])))
            v=dict(nonce=N,files=files,journal=b'',pcap=b'',task=dict(nonce=N,state=3,instanceGuids=[]),ras='No connections',bfe=b'<wfpstate/>')
            a=Adapter(pathlib.Path(__file__).parent,out,N,FirstFailure(),collect=lambda _:copy.deepcopy(v),rpc=lambda *args:self.fail('No supervisor RPC allowed'))
            freeze_controller_drain(out,N,{},{});proof=a.verify_drain(N)
            self.assertEqual(check_exact_drain(proof,N)['status'],'PASS')
            self.assertEqual(check_independent_absence(a.final(None),None,N)['status'],'PASS')
            broken=copy.deepcopy(proof);broken['files']['inspector-final.json']=encode(dict(nonce=N,launchNeverOccurred=False,launch={},processes=[]))
            self.assertNotEqual(check_exact_drain(broken,N)['status'],'PASS')

    def test_missing_and_mutated_controls_refuse(self):
        v,*_=fixture();pre=dict(probeSHA256=sha((pathlib.Path(__file__).parent/'probe.ps1').read_bytes()),nonce=N,configSHA256='c'*64,once=encode(dict(configSHA256='c'*64)))
        self.assertTrue(check_causal_admission(v,pre,v,N)['admitted'])
        packets=[];offset=24
        while offset<len(v['pcap']):
            size=struct.unpack('<I',v['pcap'][offset+8:offset+12])[0];packets.append(v['pcap'][offset:offset+16+size]);offset+=16+size
        for missing in range(len(packets)):
            broken=copy.deepcopy(v);broken['pcap']=v['pcap'][:24]+b''.join(packet for i,packet in enumerate(packets) if i!=missing)
            if missing%12<2: self.assertFalse(check_causal_admission(broken,pre,broken,N)['admitted'],missing)
        for key in ('original-producer-pin.json','reader-barrier-ready.json'):
            broken=copy.deepcopy(v);del broken['files'][key]
            self.assertFalse(check_causal_admission(broken,pre,broken,N)['admitted'])
        self.assertNotEqual(check_exact_drain(dict(wrapper=b'{}',files={}),N)['status'],'PASS')

if __name__=='__main__':unittest.main()

