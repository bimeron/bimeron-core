"""Copy gate evidence to a new immutable host directory; no gate publication."""
import argparse,json,os,pathlib,subprocess,hashlib,time
ap=argparse.ArgumentParser();ap.add_argument('--nonce',required=True);ap.add_argument('--output',required=True);ap.add_argument('--supervision',required=True);ap.add_argument('--barrier',required=True);ap.add_argument('--pin',required=True);ap.add_argument('--ssh',required=True);a=ap.parse_args()
if len(a.nonce)!=64 or any(c not in '0123456789abcdef' for c in a.nonce):raise ValueError('nonce')
out=pathlib.Path(a.output);out.mkdir(parents=True,exist_ok=False);here=pathlib.Path(__file__).resolve().parent
# Run independently of supervise.py, whose per-second heartbeat continues.
cmd=[r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(here/'copy-guest.ps1'),'-Nonce',a.nonce,'-Output',str(out.resolve())]
from windows_powershell import environment as powershell_environment
p=subprocess.run(cmd,capture_output=True,timeout=15,env=powershell_environment());(out/'guest-copy.log').write_bytes(p.stdout+p.stderr)
if p.returncode:raise RuntimeError('guest evidence copy failed')
k=pathlib.Path(os.environ['LOCALAPPDATA'])/'Bimeron/step8-observer-20261103'
ssh=[__import__('live_prepare').absolute_executable(a.ssh,'ssh'),'-F','none','-o','BatchMode=yes','-o','ConnectTimeout=3','-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=step8-observer','-o','UserKnownHostsFile='+str(k/'known_hosts2'),'-i',str(k/'client2'),'lab@192.168.196.130','sudo','python3','-',a.nonce]
program='''import pathlib,sys,struct
p=pathlib.Path('/var/lib/step8')/('run-'+sys.argv[1])/'ingress.pcap'
with p.open('rb') as f:b=f.read(64*1024*1024+1)
if len(b)>64*1024*1024:raise ValueError('capture bound')
if b[:4]==bytes.fromhex('d4c3b2a1'):e='<'
elif b[:4]==bytes.fromhex('a1b2c3d4'):e='>'
else:raise ValueError('unsupported pcap')
if len(b)<24:raise ValueError('pcap header')
pos=24
while pos+16<=len(b):
 n=struct.unpack_from(e+'IIII',b,pos)[2]
 if n>262144:raise ValueError('packet extent')
 if pos+16+n>len(b):break
 pos+=16+n
sys.stdout.buffer.write(b[:pos])
'''
before=time.time();p=subprocess.run(ssh,input=program.encode(),capture_output=True,timeout=8);after=time.time()
if p.returncode:raise RuntimeError(p.stderr.decode())
(out/'predial.pcap').write_bytes(p.stdout);(out/'snapshot-bracket.json').write_text(json.dumps(dict(hostBefore=before,hostAfter=after,nonce=a.nonce)))
for name in ['guest.jsonl','observer.jsonl','heartbeat.jsonl','binding-original.json','binding-original.sha256']:
 (out/name).write_bytes((pathlib.Path(a.supervision)/name).read_bytes())
entries=[dict(Path=p.name,SHA256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in out.iterdir() if p.is_file()]
from coverage import inventory
barrier=pathlib.Path(a.barrier).read_bytes();pin=pathlib.Path(a.pin).read_bytes()
b=json.loads(barrier);identity=json.loads(pin.decode('utf-8-sig'))
if b['nonce']!=a.nonce or identity['nonce']!=a.nonce:raise ValueError('Barrier/pin nonce')
(out/'barrier.json').write_bytes(barrier);(out/'producer-pin.json').write_bytes(pin)
(out/'coverage.json').write_text(json.dumps(inventory((out/'probe.jsonl').read_bytes(),a.nonce,identity['producer'],b['sequence']),indent=2))
entries=[dict(Path=p.name,SHA256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in out.iterdir() if p.is_file()]
(out/'manifest.json').write_text(json.dumps(entries,indent=2));print(out)


