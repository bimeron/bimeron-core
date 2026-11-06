"""One-shot, file-backed transport observation. Uncertainty never terminates a child."""
import hashlib,json,os,pathlib,subprocess,time,math
from process_handles import ChildHandle
class Uncertain(RuntimeError):pass

def retain(path,value):
 if len(os.path.abspath(path))>259:raise Uncertain('Path exceeds MAX_PATH budget: '+str(path))
 with path.open('x',encoding='utf-8') as f:
  json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())

class Transport:
 def __init__(self,out,deadline,clock=time.monotonic,sleep=time.sleep,popen=None,identity=None):
  self.out=pathlib.Path(out);self.deadline=deadline;self.clock=clock;self.sleep=sleep
  self.popen=popen or subprocess.Popen;self.identity=identity or ChildHandle
  self.children=[];self.sequence=0;self.failed=False;self.closed=False
 def observe(self,args,label,data=b'',env=None,timeout=15,before_spawn=None,mutation=False):
  if self.failed or self.closed:raise Uncertain('Transport is closed/uncertain; continuation forbidden')
  if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=150:raise ValueError('Invalid observation bound')
  self.sequence+=1;prefix=self.out/(f'transport-{self.sequence:03d}-'+label)
  paths={k:str(prefix.with_suffix('.'+k)) for k in ('stdin','stdout','stderr')}
  record=dict(argv=list(args),inputSHA256=hashlib.sha256(data).hexdigest(),inputLength=len(data),commandSHA256=hashlib.sha256(json.dumps(list(args),ensure_ascii=True).encode()).hexdigest(),mutation=mutation,files=paths,identity=None,pid=None)
  child=None;handle=None;state=dict(process=None,handle=None,record=record,prefix=prefix)
  try:
   require_budget=self.clock()+timeout<self.deadline
   if not require_budget:raise Uncertain('Insufficient original deadline')
   end=min(self.clock()+timeout,self.deadline)
   retain(prefix.with_suffix('.intent.json'),record)
   with open(paths['stdin'],'xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
   with open(paths['stdin'],'rb') as inp,open(paths['stdout'],'xb') as out,open(paths['stderr'],'xb') as err:
    if before_spawn:before_spawn()
    if self.clock()+timeout>=self.deadline:raise Uncertain('Deadline exhausted before spawn')
    # No pipes, context-managed Popen, shell, communicate, wait, kill or terminate.
    child=self.popen(list(args),stdin=inp,stdout=out,stderr=err,env=env,shell=False,close_fds=True,creationflags=subprocess.CREATE_NO_WINDOW)
    state['process']=child;self.children.append(state);record['pid']=child.pid
   retain(prefix.with_suffix('.spawn.json'),dict(pid=child.pid,files=paths,identityStatus='pending'))
   handle=self.identity(child);state['handle']=handle
   record['identity']=dict(pid=child.pid,creationFileTime=handle.creation,image=handle.exe,commandSHA256=record['commandSHA256'],commandSource='exact original Popen argv; shell false')
   retain(prefix.with_suffix('.identity.json'),record['identity'])
   while True:
    code=child.poll()
    if code is not None:
     retain(prefix.with_suffix('.result.json'),dict(returncode=code,terminationObserved=True,files=paths))
     if code:raise Uncertain('Transport exited nonzero; no continuation')
     # Read regular files after observed direct-child exit, never wait for pipe EOF.
     if self.clock()>=end:raise Uncertain('Termination observed after observation deadline')
     output=pathlib.Path(paths['stdout']);size=output.stat().st_size
     if size>16*1024*1024:raise Uncertain('Output exceeds bounded read size')
     with output.open('rb') as f:return f.read(size)
    if self.clock()>=end:raise Uncertain('Observation timeout; surviving transport unresolved')
    self.sleep(min(.05,max(0,end-self.clock())))
  except BaseException as exc:
   self.failed=True
   retain(prefix.with_suffix('.uncertain.json'),dict(error=type(exc).__name__,reason=str(exc),pid=record['pid'],identity=record['identity'],files=paths,outputStatus='obtainable file streams; may continue growing; no final digest',survivingOwnership='unresolved',sessionClosure='unproven',continuation='forbidden; separately reviewed disposition required'))
   raise
 def close(self):
  if self.closed:return
  self.closed=True
  errors=[]
  for state in self.children:
   code=None;observation='unavailable'
   try:
    code=state['process'].poll();observation='termination-observed' if code is not None else 'surviving-unresolved'
   except BaseException:pass
   try:
    retain(state['prefix'].with_suffix('.observer-exit.json'),dict(pid=state['record']['pid'],identity=state['record']['identity'],observation=observation,returncode=code,authority='no transfer; no automatic recovery',files=state['record']['files']))
   except BaseException as exc:errors.append(type(exc).__name__)
   finally:
    if state['handle'] is not None:state['handle'].close()
  if errors:raise Uncertain('Observer exit evidence incomplete: '+','.join(errors))
