"""After committed readback, freeze a causal complete-record barrier. No launch."""
import argparse,hashlib,json,pathlib,subprocess,time
from windows_powershell import environment as powershell_environment
from records import snapshot
ap=argparse.ArgumentParser();ap.add_argument('--nonce',required=True);ap.add_argument('--pin',required=True);ap.add_argument('--gate-request',required=True);ap.add_argument('--output',required=True);a=ap.parse_args()
out=pathlib.Path(a.output);out.mkdir(exist_ok=False,parents=True);here=pathlib.Path(__file__).resolve().parent
request=pathlib.Path(a.gate_request).read_bytes();gate=json.loads(request)
if gate['Nonce']!=a.nonce:raise ValueError('Gate nonce')
pin=json.loads(pathlib.Path(a.pin).read_text(encoding='utf-8-sig'))
before=time.monotonic()
p=subprocess.run([r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(here/'guest-read.ps1'),'-Mode','snapshot','-Nonce',a.nonce,'-Output',str((out/'probe.jsonl').resolve())],capture_output=True,timeout=15,env=powershell_environment())
after=time.monotonic();(out/'reader.log').write_bytes(p.stdout+p.stderr)
if p.returncode:raise ValueError('Barrier snapshot failed')
data=(out/'probe.jsonl').read_bytes();v=snapshot(data,a.nonce,pin['producer'])
if not v['records'] or v['partialBytes']:raise ValueError('Barrier incomplete record boundary')
value=dict(nonce=a.nonce,sequence=v['records'][-1]['sequence'],round=v['records'][-1]['round'],before=before,after=after,probeSHA256=hashlib.sha256(data).hexdigest(),gateSHA256=hashlib.sha256(request).hexdigest())
with (out/'barrier.json').open('xb') as f:
 import os
 f.write(json.dumps(value).encode());f.flush();os.fsync(f.fileno())
