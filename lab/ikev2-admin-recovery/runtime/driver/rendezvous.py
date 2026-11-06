import json,os,pathlib,time
from records import unique
ROLES=('supervisor','collector','barrier')
def release(root,nonce,timeout=8):
 root=pathlib.Path(root);deadline=time.monotonic()+timeout
 while True:
  found={}
  for role in ROLES:
   path=root/(role+'.ready')
   if path.exists():
    value=json.loads(path.read_text(),object_pairs_hook=unique)
    if value!={'nonce':nonce,'role':role}:raise ValueError('Stale/wrong-role readiness')
    found[role]=value
  if len(found)==3:break
  if time.monotonic()>=deadline:raise ValueError('Missing readiness before deadline')
  time.sleep(.02)
 data=json.dumps(dict(nonce=nonce,roles=list(ROLES))).encode()
 # Atomic no-replace publication after complete bytes are flushed.
 temporary=root/'readers.dispatch.pending'
 with temporary.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 os.link(temporary,root/'readers.dispatch')
 temporary.unlink()
