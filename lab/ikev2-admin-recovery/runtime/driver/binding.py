"""Latch initial trust once; changed/missing trust cannot recover within a run."""
import datetime,hashlib,json,os,pathlib,re,uuid
class Incomplete(ValueError):pass

def unique_object(pairs):
 result={}
 for k,v in pairs:
  if k in result:raise ValueError('duplicate binding key')
  result[k]=v
 return result

def validate(value):
 if not isinstance(value,dict):raise ValueError('binding must be object')
 if not {'owner','capture','guids'}<=value.keys():raise Incomplete('initial binding incomplete')
 if set(value)!={'owner','capture','guids'}:raise ValueError('unknown binding field')
 owner=value['owner'];capture=value['capture'];guids=value['guids']
 for obj,keys in [(owner,{'pid','start','path'}),(capture,{'pid','start','boot','command'})]:
  if not isinstance(obj,dict):raise ValueError('identity must be object')
  if not keys<=obj.keys():raise Incomplete('initial identity incomplete')
  if set(obj)!=keys:raise ValueError('unknown identity field')
  if type(obj['pid']) is not int or not 0<obj['pid']<=0xffffffff:raise ValueError('invalid PID')
 if owner['path']!=r'C:\BimeronStep10ProbeNative\step10-candidate.exe':raise ValueError('owner path mismatch')
 if not isinstance(owner['start'],str):raise ValueError('owner start type')
 start=datetime.datetime.fromisoformat(owner['start'].replace('Z','+00:00'))
 if start.tzinfo is None or start.utcoffset()!=datetime.timedelta(0):raise ValueError('owner start must be UTC')
 if not isinstance(capture['start'],str) or not re.fullmatch('[0-9]+',capture['start']) or int(capture['start'])<=0:raise ValueError('capture start ticks')
 if not isinstance(capture['boot'],str) or str(uuid.UUID(capture['boot']))!=capture['boot'].lower():raise ValueError('capture boot UUID')
 if not isinstance(capture['command'],str) or not re.fullmatch('[0-9a-f]{64}',capture['command']):raise ValueError('capture command hash')
 if not isinstance(guids,list) or len(guids)!=22:raise ValueError('exactly22 GUIDs required')
 canonical=[]
 for g in guids:
  if not isinstance(g,str) or str(uuid.UUID(g))!=g.lower():raise ValueError('GUID syntax')
  if uuid.UUID(g).int==0:raise ValueError('zero GUID')
  canonical.append(g.lower())
 if len(set(canonical))!=22:raise ValueError('duplicate GUID')
 return value

def publish_once(path,data):
 # Hard-link publication is atomic/no-replace on this same local filesystem.
 # Short fixed-length temporary independent of the target name (MAX_PATH).
 tmp=path.with_name('.'+uuid.uuid4().hex[:8]+'.tmp')
 if len(os.path.abspath(path))>259 or len(os.path.abspath(tmp))>259:raise ValueError('Path exceeds MAX_PATH budget')
 with tmp.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 try:os.link(tmp,path)
 finally:tmp.unlink()

class BindingLatch:
 def __init__(self,path,evidence):
  self.path=pathlib.Path(path);self.evidence=pathlib.Path(evidence);self.raw=None;self.value=None;self.failure=None
 def poll(self):
  if self.failure:raise ValueError(self.failure)
  try:raw=self.path.read_bytes()
  except FileNotFoundError:
   if self.raw is None:raise Incomplete('awaiting initial binding')
   self.failure='latched binding disappeared';raise ValueError(self.failure)
  except OSError as e:
   self.failure='binding read failed: '+str(e);raise ValueError(self.failure)
  if self.raw is not None:
   if raw!=self.raw:self.failure='latched binding bytes changed';raise ValueError(self.failure)
   return self.value
  try:value=json.loads(raw,object_pairs_hook=unique_object)
  except json.JSONDecodeError:raise Incomplete('initial binding JSON incomplete or malformed; not pinned')
  except Exception as e:self.failure='malformed binding: '+str(e);raise ValueError(self.failure)
  try:validate(value)
  except Incomplete:raise
  except Exception as e:self.failure='invalid binding: '+str(e);raise ValueError(self.failure)
  try:
   publish_once(self.evidence/'binding-original.json',raw)
   publish_once(self.evidence/'binding-original.sha256',(hashlib.sha256(raw).hexdigest()+'\n').encode())
  except Exception as e:self.failure='binding evidence publication failed: '+str(e);raise ValueError(self.failure)
  self.raw=raw;self.value=value
  return self.value
