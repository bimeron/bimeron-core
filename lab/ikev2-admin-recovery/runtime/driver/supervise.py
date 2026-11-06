"""Read-only host supervisor; never publishes a gate decision or starts lab traffic."""
import argparse,concurrent.futures,ctypes,datetime,json,os,pathlib,subprocess,time
import base64
from records import Progress

def clock():
 a=ctypes.c_ulong();i=ctypes.c_ulong();d=ctypes.c_int()
 if not ctypes.windll.kernel32.GetSystemTimeAdjustment(ctypes.byref(a),ctypes.byref(i),ctypes.byref(d)):raise OSError('clock increment unavailable')
 return dict(utc=time.time(),mono=time.monotonic(),increment=i.value/1e7)

def bounds(before,after,remote):
 guard=max(.1,2*before['increment'],2*after['increment'],2*remote['increment'])
 if after['mono']-before['mono']>6:raise ValueError('query exceeded six seconds')
 if abs((after['utc']-before['utc'])-(after['mono']-before['mono']))>guard:raise ValueError('host clock discontinuity')
 return [remote['utc']-after['utc']-2*guard,remote['utc']-before['utc']+2*guard],guard

def continuity(previous,current,guard):
 if previous is None:return
 elapsed=current['mono']-previous['mono']
 if elapsed<0 or elapsed>10:raise ValueError('clock sample gap')
 if abs(current['utc']-previous['utc']-elapsed)>2*guard:raise ValueError('remote UTC/monotonic discontinuity')

def health(guest,observer,expected,previous_probe=None):
 h=observer['health']
 if not h['Healthy'] or observer['zombie'] or observer['live']!=observer['identity'] or observer['identity']!=expected['capture']:raise ValueError('capture identity/health')
 stamp=datetime.datetime.fromisoformat(h['CheckedAt']).timestamp()
 if not 0<=observer['clock']['utc']-stamp<=6:raise ValueError('stale capture health')
 if guest['owners']!=[expected['owner']]:raise ValueError('owner identity')
 if previous_probe is not None and guest['probeLength']<=previous_probe:raise ValueError('probe stalled')
 if not all(g.lower() in guest['bfe'].lower() for g in expected['guids']):raise ValueError('owned WFP readback incomplete')

def invoke(cmd,stdin=None,env=None):
 before=clock()
 p=subprocess.run(cmd,input=stdin,text=True,capture_output=True,timeout=6,env=env)
 after=clock()
 if p.returncode:raise RuntimeError(p.stderr[-2000:])
 value=json.loads(p.stdout);remote=value.get('clock',value)
 interval,guard=bounds(before,after,remote)
 return dict(before=before,after=after,value=value,offset=interval,guard=guard)

from binding import BindingLatch

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--ssh',required=True);ap.add_argument('--nonce',default='');ap.add_argument('--expected');ap.add_argument('--producer-pin');ap.add_argument('--capture-pin');ap.add_argument('--clock-only',action='store_true');ap.add_argument('--samples',type=int,default=0);args=ap.parse_args()
 if not args.clock_only and (len(args.nonce)!=64 or any(c not in '0123456789abcdef' for c in args.nonce)):raise ValueError('nonce')
 root=pathlib.Path(args.output);root.mkdir(exist_ok=False,parents=True)
 here=pathlib.Path(__file__).resolve().parent;k=pathlib.Path(os.environ['LOCALAPPDATA'])/'Bimeron/step8-observer-20261103'
 ssh=[__import__('live_prepare').absolute_executable(args.ssh,'ssh'),'-F','none','-o','BatchMode=yes','-o','ConnectTimeout=3','-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=step8-observer','-o','UserKnownHostsFile='+str(k/'known_hosts2'),'-i',str(k/'client2'),'lab@192.168.196.130','sudo','python3','-',*([args.nonce] if not args.clock_only else [])]
 commands={'guest':([r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(here/'guest-read.ps1'),'-Mode','clock' if args.clock_only else 'state','-Nonce',args.nonce],None),'observer':(ssh,(here/'observer-read.py').read_text())}
 # Windows PowerShell 5.1 children never inherit a PowerShell 7 module path.
 environments={'guest':__import__('windows_powershell').environment(commands['guest'][0][0]),'observer':None}
 pending={};latest={};previous={};last_submit={};rounds=0
 progress=Progress();sticky=None;readiness=False
 pin_raw=None if args.clock_only else pathlib.Path(args.producer_pin).read_bytes()
 pin=None if args.clock_only else json.loads(pin_raw.decode('utf-8-sig'))
 capture_raw=None if args.clock_only else pathlib.Path(args.capture_pin).read_bytes()
 capture_pin=None if args.clock_only else json.loads(capture_raw)
 if pin is not None and pin['nonce']!=args.nonce:raise ValueError('Producer pin nonce')
 latch=None if args.clock_only else BindingLatch(args.expected,root)
 # Separate bounded child queries keep the host heartbeat progressing even if a
 # remoting or evidence command blocks. Only our read-only local query is timed out.
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
  while True:
   now=time.monotonic()
   for name,(cmd,data) in commands.items():
    if name in pending and pending[name].done():
     try:
      item=pending.pop(name).result();c=item['value'].get('clock',item['value']);continuity(previous.get(name),c,item['guard']);previous[name]=c
      if name in latest and latest[name].get('ok') and (item['offset'][0]>latest[name]['offset'][1] or item['offset'][1]<latest[name]['offset'][0]):raise ValueError('disjoint guarded offset bounds')
      if name=='guest' and not args.clock_only:
       guest=item['value']
       if guest['pin']!=pin:raise ValueError('Producer pin changed')
       ph=guest['producerHealth']
       if not ph['healthy'] or ph['failure'] or not 0<=guest['clock']['utc']-datetime.datetime.fromisoformat(ph['utc'].replace('Z','+00:00')).timestamp()<=6:raise ValueError('Producer inspector unhealthy/stale')
       parsed=progress.observe(base64.b64decode(guest['probe'],validate=True),args.nonce,pin['producer'],now)
       item['completeRecords']=len(parsed['records']);item['completeRounds']=parsed['rounds'];item['partialBytes']=parsed['partialBytes']
      latest[name]=dict(ok=True,received=now,**item)
     except Exception as e:
      latest[name]=dict(ok=False,received=now,error=str(e));pending.pop(name,None)
      if readiness:sticky=sticky or str(e)
     with (root/(name+'.jsonl')).open('a') as f:f.write(json.dumps(latest[name])+'\n');f.flush();os.fsync(f.fileno())
    if name not in pending and now-last_submit.get(name,-100)>2:
     pending[name]=pool.submit(invoke,cmd,data,environments[name]);last_submit[name]=now
   healthy=all(n in latest and latest[n]['ok'] and now-latest[n]['received']<=8 for n in commands)
   if not args.clock_only:
    try:
     if pathlib.Path(args.producer_pin).read_bytes()!=pin_raw or pathlib.Path(args.capture_pin).read_bytes()!=capture_raw:raise ValueError('Startup pin bytes changed')
    except Exception as exc:sticky=sticky or str(exc)
    if healthy and progress.ready:
     observer=latest['observer']['value']
     if not observer['health']['Healthy'] or observer['zombie'] or observer['live']!=observer['identity'] or observer['identity']!=capture_pin:sticky=sticky or 'Capture unhealthy'
     else:readiness=True
    if readiness and not healthy:sticky=sticky or 'Readiness coverage gap'
   reason='clock-only' if args.clock_only else 'awaiting explicit owner/capture/GUID binding'
   if not args.clock_only:
    try:
     expected=latch.poll()
     if healthy:health(latest['guest']['value'],latest['observer']['value'],expected);reason='readbacks valid; coordinator still must assess coverage'
    except Exception as e:
     healthy=False;reason=str(e)
     if latch.raw is not None:sticky=sticky or str(e)
   if sticky:healthy=False;reason=sticky
   with (root/'heartbeat.jsonl').open('a') as f:f.write(json.dumps(dict(utc=time.time(),mono=now,healthy=healthy,reason=reason,ready=readiness,sticky=sticky))+'\n');f.flush();os.fsync(f.fileno())
   rounds+=1
   if args.samples and rounds>=args.samples:return
   time.sleep(1)
if __name__=='__main__':main()
