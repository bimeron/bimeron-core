"""Audit no-WFP preparation only. Never emits protection PASS."""
import argparse,json,pathlib,hashlib,datetime,base64
from records import snapshot,TARGETS
from offline_evidence import assess
ap=argparse.ArgumentParser();ap.add_argument('--capture',required=True);ap.add_argument('--guest',required=True);a=ap.parse_args()
c=pathlib.Path(a.capture);g=pathlib.Path(a.guest)
n=(c/'nonce.txt').read_text();pin=json.loads((g/'logs/producer-pin.json').read_text(encoding='utf-8-sig'))
if pin['nonce']!=n:raise ValueError('Nonce mismatch')
v=snapshot((g/'logs'/('probe-'+n+'.jsonl')).read_bytes(),n,pin['producer'])
beats=[json.loads(x) for x in (c/'heartbeat.jsonl').read_text().splitlines()]
gap=max([b['mono']-a['mono'] for a,b in zip(beats,beats[1:])],default=0)
if gap>10 or any(x['failure'] for x in beats):raise ValueError('Host supervision gap')
health=[json.loads(x) for x in (g/'logs/producer-health.jsonl').read_text(encoding='utf-8-sig').splitlines()]
ready=[h for h in health if h['ready']]
if not ready or not all(h['healthy'] for h in ready[:-1]) or ready[-1]['failure']!='Pinned process exited':raise ValueError('Producer lifetime health')
packets=assess((c/'ingress.pcap').read_bytes(),n,'0','9999999999')
seen={}
for p in packets['records']:
 for r in p['rounds']:
  kind='tcp' if p['protocol']==6 else 'udp'
  if p['dst']=='<LAB_PUBLIC_IP>' and p['sport']==p['dport']:kind='carrier'
  seen.setdefault(int(r),set()).add(f"{kind}/{p['dst']}/{p['dport']}")
complete=[r for r in v['rounds'] if TARGETS<=seen.get(r['round'],set())]
result=dict(scope='NO-WFP preparation, not protection acceptance',nonce=n,records=len(v['records']),rounds=len(v['rounds']),positiveCompleteRounds=[r['round'] for r in complete],maxHostHeartbeatGap=gap,producerExit='expected finite completion; sticky unhealthy and unusable for predial',partialBytes=v['partialBytes'],packetLimitations=packets['limitations'],perRound={str(k):sorted(v) for k,v in seen.items()})
if (c/'independent-stop.jsonl').exists():
 independent=[json.loads(x) for x in (c/'independent-heartbeat.jsonl').read_text().splitlines()]
 result['maxIndependentHeartbeatGap']=max(b['mono']-a['mono'] for a,b in zip(independent,independent[1:]))
 if result['maxIndependentHeartbeatGap']>10 or any(x['failure'] for x in independent):raise ValueError('Independent supervision gap/failure')
 stopped=json.loads((c/'independent-stop.jsonl').read_text().splitlines()[-1])
 if stopped['failure']:raise ValueError('Independent stop retains failure')
 before=json.loads((g/'policy-before.json').read_text(encoding='utf-8-sig'));after=json.loads((g/'policy-after.json').read_text(encoding='utf-8-sig'))
 if before!=after:raise ValueError('Execution policy changed')
 result['policyUnchanged']=True
 prior=json.loads((pathlib.Path('<LAB_STEP9_ABI_ROOT>')/'run-03402f6d17957406425a2308dcfb9b11006c798ddee8bddc65dbd507ccf3272d/expected.json').read_text())['guids']
 for name in ('preflight-bfe.xml','cleanup-bfe.xml'):
  data=(g/name).read_bytes();text=data.decode('utf-16') if data[:2] in (b'\xff\xfe',b'\xfe\xff') else data.decode('utf-8-sig')
  if any(guid.lower() in text.lower() for guid in prior):raise ValueError('Previous GUID present')
 result['previous22GUIDsAbsentBeforeAndAfter']=True
if (c/'supervisor.stdout').exists():
 bodies=[json.loads((c/(name+'.stdout')).read_text(encoding='utf-8-sig')) for name in ('supervisor','collector','barrier')]
 starts=[datetime.datetime.fromisoformat(b['readBefore'].replace('Z','+00:00')).timestamp() for b in bodies]
 ends=[datetime.datetime.fromisoformat(b['readAfter'].replace('Z','+00:00')).timestamp() for b in bodies]
 result['allReaderHandlesOverlapSeconds']=min(ends)-max(starts)
 for name in ('collector','barrier'):
  parsed=snapshot((c/(name+'.jsonl')).read_bytes(),n,pin['producer'])
  if any(r['kind']=='end' for r in parsed['records']):raise ValueError('Reader ran after producer completion')
 parsed=snapshot(base64.b64decode(bodies[0]['probe']),n,pin['producer'])
 if any(r['kind']=='end' for r in parsed['records']):raise ValueError('Supervisor read after completion')
(c/'preparation-audit.json').write_text(json.dumps(result,indent=2))
(c/'preparation-audit.json').write_text(json.dumps(result,indent=2))
print(json.dumps({k:v for k,v in result.items() if k!='perRound'}))
if result.get('allReaderHandlesOverlapSeconds',1)<=0:raise SystemExit(1)
