"""Offline synthetic packets and mocked challenge transport; never native/VM calls."""
import copy
import json
import pathlib
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
from test_integration import fixture, N
from protected_transport import Adapter, encode, sha, Hold
from protected_evidence import _causal_hits, check_causal_admission
from persistent import FirstFailure
from records import snapshot
from preexisting import EXACT, coverage, continuity, validate_fence, payload, decode_payload
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import validate

def specimen(count=310):
    v,rows,add,journal,pcap=fixture()
    owner=dict(pid=42,creationFileTime='123',path='owner',sha256='b'*64)
    ack=b'ack';pin=v['files']['original-producer-pin.json']
    challenge=encode(dict(schema='c1pe-challenge-v1',nonce=N,measurementNonce='c'*64,requestId='d'*32,producerPinSHA256=sha(pin),policySHA256='e'*64,ackSHA256=sha(ack),owner=owner,producer=v['pin']['producer']))
    rows.append(dict(rows[-1],sequence=len(rows)+1,kind='post-arm-fence',status='consumed',ticks=rows[-1]['ticks']+1,
        detail=dict(challengeSHA256=sha(challenge),requestId='d'*32,measurementNonce='c'*64,frequency=1,sockets=[r['detail'] for r in rows if r['kind']=='socket-open'])))
    fence=rows[-1];base=fence['ticks']
    for rnd in range(4,4+count):
        first=len(rows);add(rnd)
        for i,r in enumerate(rows[first:]):r['ticks']=base+(rnd-3)+i/100
    # Journal ticks are integer Stopwatch values. Use a 1000 Hz monotonic fixture.
    for r in rows:r['ticks']=round(r['ticks']*1000)
    start=json.loads(rows[0]['status']);start['frequency']=1000;start['origin']*=1000;rows[0]['status']=json.dumps(start)
    fence['detail']['frequency']=1000
    end=dict(rows[-1],sequence=len(rows)+1,kind='measurement-end',status='complete',ticks=rows[-1]['ticks']+1)
    rows.append(end)
    for opened in [r for r in rows if r['kind']=='socket-open']:
        rows.append(dict(end,sequence=len(rows)+1,kind='socket-close',target=opened['target'],status='disposed',detail=opened['detail']))
    rows.append(dict(end,sequence=len(rows)+1,kind='end'))
    return v,rows,journal,pcap,challenge,ack,owner,fence

def raw_enclosure(root, supporting_only=False):
    """Real on-disk policy, mailbox, challenge, journal and PCAP; no verifier mocks."""
    from test_policy_full300 import Policy
    Policy.setUpClass()
    v,rows,journal,pcap,challenge,_,owner,fence=specimen(2)
    def put(name, value):
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(value if isinstance(value,bytes) else encode(value))
        return path.read_bytes()
    rules=put('protected-rules.json',Policy.rules)
    guids=put('protected-guids.json',Policy.ledger)
    put('protected-bfe.xml',Policy.xml)
    binding=dict(Nonce=N,SHA256='03b6c4dbffab2a1382344ea6fda447268d644d3adc51d34b622f572a61fccd34',
                 PolicySHA256=sha((sha(rules)+'\n'+sha(guids)).encode()))
    owner['sha256']=binding['SHA256']
    gate=put('protected-gate.json',binding)
    cfg=put('owner-transport/config.json',dict(nonce=N,ownerSHA256=binding['SHA256']))
    put('owner-transport/proofs/original-producer-pin.json',v['files']['original-producer-pin.json'])
    status=encode(dict(binding,State='OBSERVING',Errors=[]))
    events=encode(dict(Event='observation started'))+b'\n'
    responses={}
    for seq,op in ((1,'start'),(2,'sample'),(3,'sample'),(4,'sample')):
        refs=[]
        if op=='sample':
            for suffix,data in [('gate-status.json',status if seq<4 else encode(dict(binding,State='HOLD',Errors=['owner lost']))),('events.jsonl',events)]:
                name=f'{seq}-{suffix}';put('owner-transport/samples/'+name,data)
                refs.append(dict(name=name,length=len(data),sha256=sha(data)))
        command=put(f'owner-transport/commands/{seq:08d}.json',dict(seq=seq,op=op,nonce=N,configSHA256=sha(cfg)))
        response=dict(seq=seq,nonce=N,configSHA256=sha(cfg),commandSHA256=sha(command),outcome='accepted',owner=dict(owner,handleState='live'),refs=refs)
        raw=put(f'owner-transport/responses/{seq:08d}.json',response);responses[seq]=response
        put(f'owner-transport/receipts/{seq:08d}.json',dict(commandSHA256=sha(command),responseSHA256=sha(raw),beforeNS=seq*100,afterNS=seq*100+10))
    ack=put('challenge-ack.json',dict(relay=responses[1],response=responses[2],native_status=status.decode(),native_events=events.decode()))
    request=json.loads(challenge);request.update(owner=owner,policySHA256=binding['PolicySHA256'],ackSHA256=sha(ack))
    challenge=put('post-arm.json',request);fence['detail']['challengeSHA256']=sha(challenge)
    prefix=b''.join(encode(r)+b'\n' for r in rows[:fence['sequence']])
    put('barrier-000001.jsonl',prefix)
    publication=put('challenge-publication.json',dict(nonce=N,sha256=sha(challenge),name='post-arm.json'))
    put('protected-postack-fence.json',dict(sequence=fence['sequence'],round=fence['round'],probeSHA256=sha(prefix),challengeSHA256=sha(challenge),ackSHA256=sha(ack),gateSHA256=sha(gate),publicationSHA256=sha(publication),beforeNS=220,afterNS=230))
    put('protected-controls.jsonl',b''.join(encode(r)+b'\n' for r in rows[:fence['sequence']-1]))
    put('protected-controls.pcap',v['pcap'])
    # Failed local Send still has actual externally observed exact datagram.
    result=next(r for r in rows if r['kind']=='result' and r['target'] in EXACT and r['round']==4)
    result['status']='send-error:10013';result['detail'].update(bytes=0,socketError=10013)
    capture=pcap()
    if supporting_only:
        parsed=validate.e.assess(capture,N,'0','999999999999')['records'];out=capture[:24];offset=24
        for packet in parsed:
            size=struct.unpack('<I',capture[offset+8:offset+12])[0];chunk=capture[offset:offset+16+size];offset+=16+size
            if (decode_payload(bytes.fromhex(packet['payloadHex']),N) or {}).get('phase')!='POST':out+=chunk
        capture=out
    earlier=b''.join(encode(r)+b'\n' for r in rows if r['kind'] not in ('measurement-end','socket-close','end'))
    put('protected-journal-0.jsonl',earlier);put('protected-capture-0.pcap',capture)
    put('ingress.pcap',capture+b'broken')
    # Bind the actual current source closure, not a mocked source_artifacts result.
    manifest=validate.D/'source-manifest.json'
    admission=put('admission.json',dict(sourceManifest=str(manifest),freezeSHA256=sha(manifest.read_bytes()),executableSHA256=binding['SHA256']))
    put('run.json',dict(nonce=N,capture=str(root),operation='build/c1pe/operations',admissionSHA256=sha(admission)))
    return v,binding,fence,prefix,responses,status,events

class ExactTests(unittest.TestCase):
    def test_raw_earlier_escape_survives_final_failure(self):
        for final in ('missing','failed','malformed-later-command','parser','counters'):
            with self.subTest(final=final),tempfile.TemporaryDirectory() as td:
                root=pathlib.Path(td);raw_enclosure(root)
                if final=='failed':
                    t=root/'owner-transport';terminal=(root/'protected-journal-0.jsonl').read_bytes()
                    (t/'proofs/terminal.jsonl').write_bytes(terminal)
                    (root/'post-drain-sample.json').write_bytes(encode(dict(schema='c1pe-post-drain-v1',nonce=N,sequence=4,terminalSHA256=sha(terminal),statusSHA256=sha((t/'samples/4-gate-status.json').read_bytes()),eventsSHA256=sha((t/'samples/4-events.jsonl').read_bytes()))))
                if final=='malformed-later-command':(root/'owner-transport/commands/00000004.json').write_bytes(b'broken')
                if final in ('parser','counters'):
                    (root/'capture.log').write_text('60 packets captured\n'+('0' if final=='parser' else '1')+' packets dropped by kernel\n')
                result=validate.run(root)
                self.assertEqual(result['status'],'FAIL',result['gaps'])
                self.assertTrue(result['predicates']['earlierCausalEnclosure0'])
                self.assertFalse(result['predicates']['causalEnclosure'])
                self.assertTrue(result['escapes'])
                self.assertFalse(result['predicates']['completeParsingAndCounters'])

    def test_raw_missing_owner_or_changed_prefix_unresolved(self):
        for bad in ('owner','journal','capture','source'):
            with self.subTest(bad=bad),tempfile.TemporaryDirectory() as td:
                root=pathlib.Path(td);raw_enclosure(root)
                path={'owner':'owner-transport/responses/00000003.json','journal':'protected-journal-0.jsonl','capture':'protected-capture-0.pcap','source':'admission.json'}[bad]
                (root/path).write_bytes(b'{}' if bad in ('owner','source') else b'broken')
                result=validate.run(root)
                self.assertEqual(result['status'],'INCONCLUSIVE')
                self.assertFalse(result['escapes']);self.assertTrue(result['unresolvedCandidates'])

    def test_supporting_only_postfence_runtime_and_report(self):
        from protected_evidence import assess_causal_escape
        from protected_stage import Stage, Hold as StageHold
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td);v,binding,fence,prefix,responses,status,events=raw_enclosure(root,True)
            interval=dict(journal=(root/'protected-journal-0.jsonl').read_bytes(),pcap=(root/'protected-capture-0.pcap').read_bytes(),response=responses[3],native_status_bytes=status,native_status=json.loads(status),native_events=events,start_ack=dict(response=responses[2],relay=responses[1],native_status=status,native_events=events))
            assessment=assess_causal_escape(interval,v,binding,fence,prefix)
            self.assertEqual(assessment['status'],'FAIL')
            self.assertEqual({h['target'] for h in assessment['escapes']},validate.TARGETS-EXACT)
            stage=Stage.__new__(Stage);stage.measurement=dict(status='INCONCLUSIVE')
            with self.assertRaisesRegex(StageHold,'CAUSAL_ORDINARY_ESCAPE'):stage._measurement(assessment)
            stage._measurement(dict(status='INCONCLUSIVE'))
            self.assertEqual(stage.measurement['status'],'FAIL')
            result=validate.run(root)
            self.assertEqual(result['status'],'FAIL',result['gaps'])
            self.assertFalse(result['escapes'])
            self.assertEqual({h['target'] for h in result['supportingFindings']['escapes']},validate.TARGETS-EXACT)

    def test_full_interval(self):
        v,rows,journal,_,c,a,o,f=specimen()
        log=snapshot(journal(),N,v['pin']['producer'])
        validate_fence(c,rows,N,v['files']['original-producer-pin.json'],'e'*64,a,o)
        result,duration=coverage(log,f)
        self.assertGreaterEqual(duration,300)
        self.assertEqual({x['attempts'] for x in result.values()},{310})
        self.assertEqual(len({r['target'] for r in rows if r['kind']=='attempt'}),12)

    def test_continuity_negatives(self):
        v,rows,*_=specimen(3)
        for case in ('replacement','same-handle-reuse','peer','missing-close','early-post','duplicate-fence','bad-error'):
            with self.subTest(case=case):
                changed=copy.deepcopy(rows)
                a=next(r for r in changed if r['kind']=='attempt' and r['target'] in EXACT)
                if case=='replacement':a['detail']['socket']=dict(a['detail']['socket'],handle='999')
                elif case=='peer':a['detail']['socket']['remote']='<LAB_PUBLIC_IP>:999'
                elif case=='same-handle-reuse':changed.insert(10,copy.deepcopy(next(r for r in changed if r['kind']=='socket-open')))
                elif case=='missing-close':changed=[r for r in changed if r['kind']!='socket-close']
                elif case=='early-post':a['detail']['phase']='POST';a['detail']['measurementNonce']='c'*64
                elif case=='duplicate-fence':changed.insert(-1,copy.deepcopy(next(r for r in changed if r['kind']=='post-arm-fence')))
                elif case=='bad-error':next(r for r in changed if r['kind']=='result' and r['target'] in EXACT)['detail']['socketError']='10013'
                with self.assertRaises(ValueError):continuity(changed,N,terminal=True)

    def test_short_skipped_gap_and_disposal_not_measurement(self):
        v,rows,journal,_,_,_,_,f=specimen(20)
        # A long disposal wait cannot make 20 seconds into 300 seconds.
        for r in rows[-3:]:r['ticks']+=400000
        with self.assertRaises(ValueError):coverage(snapshot(journal(),N,v['pin']['producer']),f)
        for case in ('skip','gap','cancel'):
            v,rows,journal,_,_,_,_,f=specimen()
            if case=='skip':rows.remove(next(r for r in rows if r['kind']=='attempt' and r['round']==5 and r['target'] in EXACT))
            if case=='gap':
                for r in rows:
                    if r['round']>=5:r['ticks']+=9000
            if case=='cancel':rows[-1]['status']='cancelled';rows[-1]['requestId']='f'*32
            with self.assertRaises(ValueError):coverage(snapshot(journal(),N,v['pin']['producer']),f)

    def test_fence_binding_negatives(self):
        v,rows,_,_,raw,ack,owner,_=specimen(1)
        for key,value in [('measurementNonce',N),('ackSHA256','0'*64),('producerPinSHA256','0'*64),('requestId','e'*32),('owner',{})]:
            c=json.loads(raw);c[key]=value
            with self.assertRaises(ValueError):validate_fence(encode(c),rows,N,v['files']['original-producer-pin.json'],'e'*64,ack,owner)

    def test_external_prearm_required_both(self):
        v,rows,add,journal,pcap=fixture()
        pre=dict(nonce=N,configSHA256='c'*64,once=encode(dict(configSHA256='c'*64)),probeSHA256=sha(pathlib.Path(__file__).with_name('probe.ps1').read_bytes()))
        self.assertTrue(check_causal_admission(v,pre,v,N)['admitted'])
        parsed=validate.e.assess(v['pcap'],N,'0','999999999999')
        for port in (500,4500):
            out=v['pcap'][:24]
            pos=24
            for packet in parsed['records']:
                size=struct.unpack('<I',v['pcap'][pos+8:pos+12])[0]
                raw=v['pcap'][pos:pos+16+size];pos+=16+size
                if not (packet['sport']==packet['dport']==port):out+=raw
            broken=dict(v,pcap=out)
            self.assertFalse(check_causal_admission(broken,pre,v,N)['admitted'])

    def test_failed_send_escape_and_malformed_tail(self):
        v,rows,journal,pcap,_,_,_,f=specimen(2)
        r=next(r for r in rows if r['kind']=='result' and r['target'] in EXACT and r['round']==4)
        r['status']='send-error:10013';r['detail']['bytes']=0;r['detail']['socketError']=10013
        _,hits=_causal_hits(pcap()+b'broken',journal()+b'{broken}\n',N,v['pin'],f)
        self.assertTrue(any(h['target']==r['target'] and h['round']==4 for h in hits))
        with self.assertRaises(ValueError):validate.packets(pcap()+b'broken',N,0)

    def test_payload_is_narrow(self):
        p=payload(N,'POST','c'*64,N+'-500',500,4)
        self.assertIsNotNone(decode_payload(p,N))
        for bad in (p+b'x',b'x'+p,p.replace(b'POST',b'PRE'),p.replace(b'|500|',b'|4500|')):self.assertIsNone(decode_payload(bad,N))

    def test_fence_before_ack_and_publication_deadline(self):
        meta=dict(beforeNS='20',afterNS='30');ack=dict(beforeNS='1',afterNS='10');post=dict(beforeNS='40',afterNS='50')
        validate.challenge_order(meta,ack,post)
        for m,a,p in [(dict(meta,beforeNS='5'),ack,post),(dict(meta,afterNS=str(21_000_000_000)),ack,post),(meta,ack,dict(post,beforeNS='25'))]:
            with self.assertRaises(ValueError):validate.challenge_order(m,a,p)

    def test_mock_bad_publication_and_missing_receipt(self):
        v,rows,_,journal,_=fixture()
        binding=dict(Nonce=N,SHA256='b'*64,PolicySHA256='e'*64)
        owner=dict(pid=42,creationFileTime='123',path='owner',sha256='b'*64)
        ack=dict(response=dict(owner=dict(owner,handleState='live')),relay=dict(outcome='accepted'),native_status=encode(dict(binding,State='OBSERVING',Errors=[])),native_events=encode(dict(Event='observation started'))+b'\n')
        for failure in ('bad-publication','no-receipt'):
            with tempfile.TemporaryDirectory() as td:
                a=Adapter('.',td,N,FirstFailure());a.controls=v;a.owner_identity=owner;a.start_ack=ack
                a._ps=lambda *args,**kwargs:encode(dict(nonce=N,sha256=('0'*64 if failure=='bad-publication' else sha(pathlib.Path(args[-1]).read_bytes())),name='post-arm.json'))
                with patch('protected_transport.time.monotonic',side_effect=[0,0,21]):
                    with self.assertRaises(Hold):a._challenge_fence(binding)
                self.assertTrue(hasattr(a,'challenge_raw'))
                with self.assertRaises(Hold):a._challenge_fence(binding)

    def test_mock_challenge_one_shot_and_after_ack(self):
        v,rows,_,journal,_=fixture()
        binding=dict(Nonce=N,SHA256='b'*64,PolicySHA256='e'*64)
        owner=dict(pid=42,creationFileTime='123',path='owner',sha256='b'*64)
        status=encode(dict(binding,State='OBSERVING',Errors=[]))
        ack=dict(response=dict(owner=dict(owner,handleState='live')),relay=dict(outcome='accepted'),native_status=status,native_events=encode(dict(Event='observation started'))+b'\n')
        with tempfile.TemporaryDirectory() as td:
            out=pathlib.Path(td);a=Adapter(pathlib.Path(__file__).parent,out,N,FirstFailure(),collect=lambda _:dict(v,journal=journal()))
            a.controls=v;a.owner_identity=owner;a.start_ack=ack
            (a.root/'proofs').mkdir(parents=True);(a.root/'proofs/gate.json').write_bytes(encode(binding))
            def publish(*args,**kwargs):
                path=pathlib.Path(args[-1]);c=json.loads(path.read_bytes())
                rows.append(dict(rows[-1],sequence=len(rows)+1,kind='post-arm-fence',status='consumed',ticks=rows[-1]['ticks']+1,detail=dict(challengeSHA256=sha(path.read_bytes()),requestId=c['requestId'],measurementNonce=c['measurementNonce'],frequency=1,sockets=[r['detail'] for r in rows if r['kind']=='socket-open'])))
                return encode(dict(nonce=N,sha256=sha(path.read_bytes()),name='post-arm.json'))
            a._ps=publish
            value=a.barrier(binding)
            self.assertEqual(json.loads(value['path'].read_bytes())['sequence'],rows[-1]['sequence'])
            with self.assertRaises(Hold):a.barrier(binding)
        with tempfile.TemporaryDirectory() as td:
            a=Adapter('.',td,N,FirstFailure());a.start_ack=dict(ack,native_status=encode(dict(binding,State='HOLD',Errors=[])))
            with patch('secrets.token_hex',side_effect=AssertionError('must not generate early')):
                with self.assertRaises(Hold):a._challenge_fence(binding)

    def test_fail_precedence_in_report(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td);(root/'run.json').write_text(json.dumps(dict(nonce=N,capture=td)))
            enclosure=dict(hits=[dict(target='carrier/<LAB_PUBLIC_IP>/500')],pin=dict(producer={}),cutoff={},post={},commands={})
            # Missing final journal, counters and raw closure must not erase FAIL.
            (root/'owner-transport/proofs').mkdir(parents=True)
            (root/'owner-transport/proofs/terminal.jsonl').write_bytes(b'bad\n')
            with patch.object(validate,'source_artifacts',return_value=True),patch.object(validate,'causal',return_value=enclosure),patch('verify_raw.verify',side_effect=ValueError('release before drain')):
                result=validate.run(root)
            self.assertEqual(result['status'],'FAIL');self.assertTrue(result['gaps'])

if __name__=='__main__':unittest.main()
