"""One bounded no-WFP preparation; explicit invocation only, no retry."""
import concurrent.futures,hashlib,json,os,pathlib,secrets,subprocess,time,threading,argparse,datetime
from settlement import await_settlement
from watcher_release import await_release
from protected_stage import Stage
from cancellation import Transport, control, publish_once
from lifecycle import wait_producer_ready
from persistent import FirstFailure,run_owned,validate_readers,stamp

from readiness_diagnostics import POWERSHELL, query as readiness_query

ap=argparse.ArgumentParser();ap.add_argument('--mode',choices=['provenance'],default='provenance');ap.add_argument('--readers-test',action='store_true');ap.add_argument('--seconds',type=int,choices=[45,900],default=45);ap.add_argument('--diagnostic-fail-after-readers-ready',action='store_true');ap.add_argument('--duration-handshake',action='store_true');ap.add_argument('--capture-path-file');args=ap.parse_args()
if args.seconds==900 and not args.duration_handshake:ap.error('900 requires --duration-handshake')
if args.diagnostic_fail_after_readers_ready and not args.readers_test:ap.error('diagnostic requires readers')
HERE=pathlib.Path(__file__).resolve().parent
nonce=administrative_owner.bound['nonce'];out=administrative_owner.journal.root
# The original admitted owner created this private root before any setup effect.
administrative_owner.journal.admission.revalidate()
if args.capture_path_file:publish_once(pathlib.Path(args.capture_path_file),dict(nonce=nonce,path=str(out)))
key=pathlib.Path(os.environ['LOCALAPPDATA'])/'Bimeron/step8-observer-20261103'
from admin_recovery import pin_ssh_inputs
pin_ssh_inputs(administrative_owner,key)
ssh=[str(administrative_owner.resources['sshExecutable']),'-F','none','-o','BatchMode=yes','-o','ConnectTimeout=3','-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=step8-observer','-o','UserKnownHostsFile='+str(key/'known_hosts2'),'-i',str(key/'client2'),'lab@192.168.196.130']
source='/home/lab/step9-03402f6d17957406425a2308dcfb9b11006c798ddee8bddc65dbd507ccf3272d'
capture=source+'/capture-supervisor.py';unit='step10-prep-'+nonce
# The Handoff retires with the same argv bytes (shared effect-once fingerprint).
administrative_owner.resources.update(ssh=list(ssh),capture=capture)
def remote(command,timeout=8):
 # Every original transport is retained by the admitted owner. This fixed
 # adapter reserves before submission and only observes its original child.
 mutation=not (command.startswith('cat ') or command.startswith('sudo cat ') or command=='hostname; sudo nft list ruleset; sudo ss -lntup' or command=='sudo python3 '+capture+' status '+nonce)
 return administrative_owner.resources['original_remote_transport'](ssh+[command],timeout,mutation=mutation)
def save(name,data): (out/name).write_bytes(data)
def cancellation_event(kind,**fields):
 path=out/'cancellation-evidence.json'
 record=json.loads(path.read_text()) if path.exists() else dict(schema=1,nonce=nonce,events=[])
 record['events'].append(dict(kind=kind,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),monotonic=time.monotonic(),**fields))
 temporary=path.with_suffix('.pending');temporary.write_text(json.dumps(record));os.replace(temporary,path)

failure=FirstFailure()
from protected_transport import Adapter, freeze
stage=Stage(HERE,out,nonce,failure,adapter=Adapter(HERE,out,nonce,failure,
 rpc=administrative_owner.resources['resident'],owned_ps=administrative_owner.resources['resident'].helper,
 administrative_owner=administrative_owner,owner_path=administrative_owner.resources.get('nativeOwner')))
save('nonce.txt',nonce.encode())
for name in ('capture-supervisor.py','sinks.py'):
 data=remote('cat '+source+'/'+name)
 if data!=administrative_owner.resources['captureSources'][name]:raise ValueError('Capture dependency changed')
 save(name,data)
save('preflight.txt',remote('hostname; sudo nft list ruleset; sudo ss -lntup'))
administrative_owner.resources['entryInventory']['captureAttempted']=True
save('capture-start.txt',remote('sudo python3 '+capture+' start '+nonce))
# Stable startup identity is checked by the unchanged capture supervisor.
time.sleep(1)
status=json.loads(remote('sudo python3 '+capture+' status '+nonce))
if not status['Healthy'] or not status['LiveIdentityHealthy']:raise ValueError('Capture not ready; retain for inspection')
save('capture-ready.json',json.dumps(status).encode());identity=status['Identity']
administrative_owner.resources['captureIdentity']=identity
config=dict(nonce=nonce,capture=identity,query=ssh+['sudo python3 '+capture+' status '+nonce],cleanup=str(out/'protected-cleanup.json'),captureFinal=str(out/'health.json'))
publish_once(out/'host-supervisor-config.json',config)
independent=administrative_owner.resources['independent']
ready_deadline=time.monotonic()+5
while not (out/'host-supervisor-identity.json').exists() and time.monotonic()<ready_deadline:time.sleep(.1)
if not (out/'host-supervisor-identity.json').exists():raise RuntimeError('Independent supervisor startup refused')
administrative_owner.resources['entryInventory']['sinkAttempted']=True
from sink_contract import start_command as sink_start_command
save('sinks-start.txt',remote(sink_start_command(nonce,source)))
ownership_drained=False;stop=threading.Event();cleaned=threading.Event()
def monitor():
 pending=None;last=time.monotonic()
 with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
  while not stop.is_set():
   now=time.monotonic()
   if pending is not None and pending.done():
    try:
     value=json.loads(pending.result())
     if not cleaned.is_set() and (not value['Healthy'] or not value['LiveIdentityHealthy'] or value['Identity']!=identity):raise ValueError('Capture unhealthy/replaced')
     last=now
     with (out/'capture-health.jsonl').open('a') as f:f.write(json.dumps(dict(host=time.time(),mono=now,value=value,cleanupConfirmed=cleaned.is_set()))+'\n')
    except Exception as exc:
     if not cleaned.is_set():failure.set(exc)
    pending=None
   if pending is None:pending=pool.submit(remote,'sudo python3 '+capture+' status '+nonce,6)
   if now-last>8 and not cleaned.is_set():failure.set('Capture health stale')
   with (out/'heartbeat.jsonl').open('a') as f:f.write(json.dumps(dict(utc=time.time(),mono=now,failure=failure.value,cleanupConfirmed=cleaned.is_set()))+'\n');f.flush();os.fsync(f.fileno())
   stop.wait(1)
thread=threading.Thread(target=monitor,daemon=True)
administrative_owner.resources['entryInventory']['monitorAttempted']=True
thread.start()
try:
 stage.start()
 with (out/'task.log').open('wb') as log:
  freeze(out/'preparation-source.ps1',(HERE/'prepare-task.ps1').read_bytes())
  command=[POWERSHELL,'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(HERE/'prepare-task.ps1'),'-Nonce',nonce,'-ControlPath',str(out),'-Mode',args.mode,'-ProducerSeconds',str(args.seconds),'-TaskDuration',('PT20M' if args.seconds==900 else 'PT3M')]
  process=administrative_owner.resources['spawn_owned']('preparation',command,stdout=log,stderr=log)
  stage.adapter.bind_preparation(process,command)
  def launch(mode,role,label):
   cmd=[POWERSHELL,'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(HERE/'guest-read.ps1'),'-Mode',mode,'-Nonce',nonce,'-ControlPath',str(out)]
   if role:cmd+=['-TestRole',role]
   cmd+=['-ClosurePath',str(out/(label+'.session-closed.json'))]
   return Transport(cmd,out,label,administrative_owner=administrative_owner)
  def validate(values):
   if args.readers_test:
    coverage=validate_readers(values,nonce)
    if any(stamp(v['terminal']['utc'])-stamp(v['producer']['start'])<args.seconds for v in values):raise ValueError('Producer duration shorter than requested interval')
    save('reader-coverage.json',json.dumps(coverage).encode())
  administrative_owner.resources['cancellation_state']={}
  administrative_owner.resources['controllerEntered']=True
  ownership_drained=control(process,launch,out,nonce,failure,args.seconds,validate,args.diagnostic_fail_after_readers_ready,args.readers_test,before_restore=stage.before_restore,retained_state=administrative_owner.resources['cancellation_state'])
  save('task-exit.txt',str(process.returncode).encode())
 
except Exception as exc:
 failure.set(exc)
finally:
 try:
  if not ownership_drained:raise RuntimeError('HOLD: owned process/readers not drained; capture retained')
  if not (out/'protected-cleanup.json').is_file():raise RuntimeError('HOLD: protected cleanup evidence missing; capture retained')
  stage.adapter.verify_preparation_exit()
  root=out/'preparation'/'guest'
  cleanup=json.loads((root/'cleanup.json').read_text(encoding='utf-8-sig'))
  if not cleanup['rasAbsent'] or not cleanup['ownerAbsent'] or not cleanup['taskReady']:raise ValueError('Cleanup uncertain')
  if args.duration_handshake:
   publish_once(out/'duration-restore-request.json',dict(schema=1,nonce=nonce))
   deadline=(failure.monotonic+60) if failure.event.is_set() else time.monotonic()+60
   while not (out/'duration-restored.json').exists():
    if time.monotonic()>=deadline:
     cancellation_event('hold',reason='duration restoration acknowledgement missing; capture/watchers retained')
     raise RuntimeError('HOLD: duration restoration acknowledgement missing; capture/watchers retained')
    time.sleep(.2)
   ack=json.loads((out/'duration-restored.json').read_text(encoding='utf-8-sig'))
   if ack.get('schema')!=1 or ack.get('nonce')!=nonce or ack.get('restored') is not True or ack.get('duration')!='PT3M':raise RuntimeError('HOLD: invalid duration acknowledgement')
  cancellation_event('duration-restored' if args.duration_handshake else 'short-duration-unchanged')
  await_settlement(out, nonce, failure, HERE.parent / 'prelaunch-baseline.json')
  await_release(out, nonce, failure)
  cleaned.set()
  # One shared effect-once ledger (fixed key, exact bytes) with the Handoff.
  from sink_contract import retirement_commands
  retirement=retirement_commands(nonce,capture)
  def retire(key):
   command,data=retirement[key]
   return administrative_owner.resources['original_remote_transport'].retire(key,ssh+[command],data)
  retire('admin-capture-confirm')
  try:
   save('capture-stop.txt',retire('admin-capture-stop'))
   cancellation_event('capture-stopped')
  finally:
   save('sinks-stop.txt',retire('admin-sink-stop'))
  time.sleep(3)
  for name in ('ingress.pcap','capture.log','health.json','health.jsonl','identity.json','startup-owned.json'):
   save(name,remote('sudo cat /var/lib/step8/run-'+nonce+'/'+name))
  sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
  save('host-supervisor-stop.json',json.dumps(dict(identity=json.loads((out/'host-supervisor-identity.json').read_text()),cleanupSHA256=sha(out/'protected-cleanup.json'),captureFinalSHA256=sha(out/'health.json'))).encode())
  try:
   independent.wait(timeout=10)
   acknowledgement=[json.loads(line) for line in (out/'independent-stop.jsonl').read_text().splitlines() if line.strip()]
   if independent.returncode or len(acknowledgement)!=1 or acknowledgement[0].get('failure'):
    failure.set('Independent watcher refused run')
  finally:
   if cleaned.is_set():stop.set();thread.join(timeout=8)
   if thread.is_alive():failure.set('Monitor did not drain; owner retained') 
  save('result.json',json.dumps(dict(taskExit=process.returncode,supervisionFailure=failure.value,nonce=nonce)).encode())
  print(out)
  if failure.value or process.returncode:raise SystemExit(1)
 finally:
  if cleaned.is_set():stop.set();thread.join(timeout=8)
