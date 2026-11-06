"""Finish only a named preparation after independently recorded guest cleanup."""
import json,os,pathlib,subprocess,sys,time,hashlib,ctypes
here=pathlib.Path(__file__).resolve().parent
if len(sys.argv)!=3:raise SystemExit('usage: finish-preparation.py NONCE ABSOLUTE-SSH-PATH')
n=sys.argv[1]
if len(n)!=64 or any(c not in '0123456789abcdef' for c in n):raise ValueError('nonce')
root=here/('prep-'+n[:16])/'guest'
if not root.exists():root=here/('prep-'+n)/n
# The admitted private run root: name from admission, bound by its run-identity.json.
from admin_recovery import bound_private_root,private_root_name
out=bound_private_root(here/private_root_name(n),n)
c=json.loads((root/'cleanup.json').read_text(encoding='utf-8-sig'))
if not all(c[k] for k in ('rasAbsent','ownerAbsent','taskReady')):raise ValueError('Uncertain cleanup')
key=pathlib.Path(os.environ['LOCALAPPDATA'])/'Bimeron/step8-observer-20261103'
ssh=[__import__('live_prepare').absolute_executable(sys.argv[2],'ssh'),'-F','none','-o','BatchMode=yes','-o','ConnectTimeout=3','-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=step8-observer','-o','UserKnownHostsFile='+str(key/'known_hosts2'),'-i',str(key/'client2'),'lab@192.168.196.130']
def run(command,data=None):
 p=subprocess.run(ssh+[command],input=b'' if data is None else data,capture_output=True,timeout=8)
 if p.returncode:raise RuntimeError(p.stderr.decode())
 return p.stdout
confirmation=json.dumps(dict(Nonce=n,OwnedRASAbsent=True,WFPOwnerCleaned=True))
program="import pathlib;pathlib.Path('/var/lib/step8/run-"+n+"/cleanup-confirmed.json').write_text("+repr(confirmation)+")"
run('sudo python3 -',program.encode())
capture='/home/lab/step9-03402f6d17957406425a2308dcfb9b11006c798ddee8bddc65dbd507ccf3272d/capture-supervisor.py'
(out/'capture-stop.txt').write_bytes(run('sudo python3 '+capture+' stop '+n))
(out/'sinks-stop.txt').write_bytes(run('sudo systemctl stop step10-prep-'+n))
time.sleep(3)
for name in ('ingress.pcap','capture.log','health.json','health.jsonl','identity.json','startup-owned.json'):
 (out/name).write_bytes(run('sudo cat /var/lib/step8/run-'+n+'/'+name))
print((out/'capture.log').read_text())

# Stop only the original retained watcher identity after verified capture/guest cleanup.
identity=json.loads((out/'host-supervisor-identity.json').read_text())
kernel=ctypes.windll.kernel32
kernel.OpenProcess.restype=ctypes.c_void_p
handle=kernel.OpenProcess(0x101000,False,identity['pid'])
if not handle:raise RuntimeError('Watcher identity unavailable; HOLD')
try:
 c=ctypes.c_ulonglong();e=ctypes.c_ulonglong();k=ctypes.c_ulonglong();u=ctypes.c_ulonglong()
 if not kernel.GetProcessTimes(ctypes.c_void_p(handle),ctypes.byref(c),ctypes.byref(e),ctypes.byref(k),ctypes.byref(u)) or c.value!=identity['startFiletime']:
  raise RuntimeError('Watcher process identity mismatch')
 final=json.loads((out/'health.json').read_text())
 if final.get('ExitCode')!=0:raise RuntimeError('Capture closure failed')
 sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
 decision=dict(identity=identity,cleanupSHA256=sha(root/'cleanup.json'),captureFinalSHA256=sha(out/'health.json'))
 stop_path=out/'host-supervisor-stop.json'
 if stop_path.exists():
  if json.loads(stop_path.read_text())!=decision:raise RuntimeError('Existing stop differs')
 else:
  with stop_path.open('x') as f:json.dump(decision,f);f.flush();os.fsync(f.fileno())
 if kernel.WaitForSingleObject(ctypes.c_void_p(handle),10000)!=0:raise RuntimeError('Watcher not drained; HOLD')
 ack=[json.loads(line) for line in (out/'independent-stop.jsonl').read_text().splitlines() if line.strip()]
 if len(ack)!=1 or ack[0].get('identity')!=identity or ack[0].get('failure'):raise RuntimeError('Watcher refused run; cleanup separate')
finally:kernel.CloseHandle(ctypes.c_void_p(handle))
