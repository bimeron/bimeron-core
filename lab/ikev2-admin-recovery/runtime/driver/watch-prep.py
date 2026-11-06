"""Independent host preparation monitor; controller failure never stops it."""
import argparse,concurrent.futures,ctypes,hashlib,json,os,pathlib,subprocess,sys,time
from watcher_release import validate_release, acknowledge
from admin_watcher_endpoint import tick as administrative_tick
from watcher_query import Query, TickJournal
from admin_recovery import decode,encode,require,same
ap=argparse.ArgumentParser();ap.add_argument('--config',required=True);ap.add_argument('--admission');a=ap.parse_args()
path=pathlib.Path(a.config);root=path.parent
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def append(name,value):
 with (root/name).open('a') as f:f.write(json.dumps(value)+'\n');f.flush();os.fsync(f.fileno())
c=ctypes.c_ulonglong();e=ctypes.c_ulonglong();k=ctypes.c_ulonglong();u=ctypes.c_ulonglong()
kernel=ctypes.windll.kernel32;kernel.GetCurrentProcess.restype=ctypes.c_void_p
if not kernel.GetProcessTimes(ctypes.c_void_p(kernel.GetCurrentProcess()),ctypes.byref(c),ctypes.byref(e),ctypes.byref(k),ctypes.byref(u)):raise OSError('Process identity')
if a.admission:
 context=decode(pathlib.Path(a.admission).read_bytes())
 require(set(context)=={'schema','nonce','configSHA256','candidateSHA256'} and context['schema']=='fresh-containment-admission-v1','Idle containment binding')
 original=dict(context=context,identity=dict(pid=os.getpid(),creationFileTime=str(c.value),imageSHA256=sha(sys.executable)))
 from watcher_release import publish
 publish(root/'containment-ready.json',encode(original))
 while not path.exists():
  abort=root/'containment-abort.json'
  if abort.exists():
   require(same(decode(abort.read_bytes()),context),'Idle abort binding')
   require(not path.exists(),'Capture admission raced idle abort')
   publish(root/'containment-aborted.json',encode(original));raise SystemExit(1)
  time.sleep(.05)
raw=path.read_bytes();cfg=json.loads(raw)
if a.admission:require(cfg['nonce']==context['nonce'],'Fresh capture config nonce')
identity=dict(pid=os.getpid(),startFiletime=c.value,exe=sys.executable,exeSHA256=sha(sys.executable),script=str(pathlib.Path(__file__).resolve()),scriptSHA256=sha(__file__),configSHA256=hashlib.sha256(raw).hexdigest(),nonce=cfg['nonce'])
with (root/'host-supervisor-identity.json').open('x') as f:json.dump(identity,f);f.flush();os.fsync(f.fileno())
failure=None;pending=None;last=time.monotonic();cleanup=False;last_value=None;released=False;last_sample=None
administrative_state={}
query=Query(root,cfg['query'])
# Every tick refusal/exception is journaled (bounded), not only the first
# failure; the sticky `failure` still records the first one.
journal=TickJournal(root);tick=0
def refuse(stage,error):
 journal.refuse(tick,stage,error)
with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
 while True:
  now=time.monotonic();tick+=1
  try:
   if path.read_bytes()!=raw:
    failure=failure or 'Supervisor config changed';refuse('config',ValueError('Supervisor config changed'))
  except OSError as exc:failure=failure or 'Supervisor config unreadable: '+str(exc);refuse('config',exc)
  cleanup_path=pathlib.Path(cfg['cleanup'])
  try:
   check=json.loads(cleanup_path.read_text(encoding='utf-8-sig'))
   cleanup=all(check[x] is True for x in ('rasAbsent','ownerAbsent','taskReady')) and check['nonce']==cfg['nonce']
   if cleanup:validate_release(root,cfg['nonce'])
  except Exception as exc:
   cleanup=False
   # Before the release request exists an unavailable cleanup is the normal state.
   if (root/'watcher-release.json').exists():refuse('cleanup',exc)
  if pending is not None and pending.done():
   try:
    sample=pending.result();last_value=sample['value'];last=sample['after'];last_sample=sample
    if not released and (not last_value['Healthy'] or not last_value['LiveIdentityHealthy'] or last_value['Identity']!=cfg['capture']):raise ValueError('Capture identity/health')
    append('independent-capture-health.jsonl',sample)
   except Exception as exc:
    if not released:failure=failure or str(exc)
    refuse('query',exc)
    try:append('independent-query-errors.jsonl',dict(utc=time.time(),error=str(exc),cleanupConfirmed=cleanup))
    except Exception as journal_error:refuse('query-journal',journal_error)
   pending=None
  if time.monotonic()-last>8 and not released:
   failure=failure or 'Capture query stale';refuse('query-stale',TimeoutError('Capture query stale'))
  if cleanup and not released and pending is None and last_sample is not None and failure is None:
   try:
    acknowledge(root,cfg['nonce'],identity,last_sample);released=True
   except Exception as exc:failure=failure or 'Release acknowledgement failed: '+str(exc);refuse('release-ack',exc)
  cleanup=cleanup and released
  # Distinct failed-run disposition. Check after collecting the original pending
  # query and before scheduling another one; never cancel a surviving query.
  try:
   if administrative_tick(root,identity,pending or query.unresolved(),administrative_state):break
  except Exception as exc:failure=failure or 'Administrative watcher proof refused: '+str(exc);refuse('administrative',exc)
  if pending is None and not released:pending=pool.submit(query)
  try:append('independent-heartbeat.jsonl',dict(utc=time.time(),mono=now,failure=failure,cleanupConfirmed=cleanup,tick=tick,tickRefusals=journal.count))
  except Exception as exc:failure=failure or 'Heartbeat unwritable: '+str(exc);refuse('heartbeat',exc)
  stop=root/'host-supervisor-stop.json'
  try:
   if stop.exists():
    decision=json.loads(stop.read_text())
    final=pathlib.Path(cfg['captureFinal'])
    if decision.get('identity')!=identity or not cleanup or not final.exists():failure=failure or 'Invalid supervisor stop request';refuse('stop',ValueError('Invalid supervisor stop request'))
    else:
     capture_final=json.loads(final.read_text())
     if capture_final.get('ExitCode')!=0 or decision.get('cleanupSHA256')!=sha(cleanup_path) or decision.get('captureFinalSHA256')!=sha(final):failure=failure or 'Unverified cleanup/capture completion';refuse('stop',ValueError('Unverified cleanup/capture completion'))
     else:
      append('independent-stop.jsonl',dict(utc=time.time(),identity=identity,failure=failure));break
  except (OSError,ValueError,TypeError,AttributeError) as exc:failure=failure or 'Supervisor stop evidence unreadable: '+str(exc);refuse('stop',exc)
  time.sleep(1)

if failure:raise SystemExit(1)
