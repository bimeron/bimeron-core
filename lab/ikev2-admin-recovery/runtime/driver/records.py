"""Strict snapshot validation and sticky progress; never issues a verdict."""
import json, re, hashlib,datetime

TARGETS = {f'{p}/{a}/{port}' for a in ('192.0.2.1','fd42:8::1')
           for p, ports in [('udp',(49000,53)),('tcp',(53,8080))] for port in ports}
TARGETS |= {f'{p}/<LAB_PUBLIC_IP>/{port}' for p in ('udp','carrier') for port in (500,4500)}

def unique(pairs):
    out = {}
    for k,v in pairs:
        if k in out: raise ValueError('Duplicate key')
        out[k] = v
    return out

def snapshot(data, nonce, identity):
    if not re.fullmatch('[a-f0-9]{64}', nonce) or len(data)>64*1024*1024: raise ValueError('Bounds')
    end=data.rfind(b'\n')+1
    tail=data[end:]
    if len(tail)>16384: raise ValueError('Oversized partial record')
    records=[]; rounds=[]; active=None; attempts=set(); results=set(); last_ticks=-1;ended=False
    for line in data[:end].splitlines():
        if len(line)>16384: raise ValueError('Oversized record')
        r=json.loads(line.decode('utf-8',errors='strict'),object_pairs_hook=unique)
        fields={'nonce','sequence','round','producer','utc','ticks','kind','target','status'}
        if r.get('kind') in ('socket-open','socket-close','post-arm-fence') or (r.get('target','').startswith('carrier/') and 'detail' in r): fields.add('detail')
        if r.get('kind')=='end' and r.get('status')=='cancelled': fields.add('requestId')
        if set(r)!=fields: raise ValueError('Record schema')
        if r['nonce']!=nonce or r['producer']!=identity: raise ValueError('Identity mismatch')
        if type(r['sequence']) is not int or r['sequence']!=len(records)+1: raise ValueError('Sequence gap')
        if type(r['ticks']) is not int or r['ticks']<last_ticks: raise ValueError('Nonmonotonic clock')
        last_ticks=r['ticks']
        if type(r['round']) is not int or r['round']<0: raise ValueError('Round type')
        kind=r['kind']; target=r['target']
        if not isinstance(r['status'],str) or not isinstance(r['utc'],str): raise ValueError('Record types')
        stamp=datetime.datetime.fromisoformat(r['utc'].replace('Z','+00:00'))
        if stamp.tzinfo is None or stamp.utcoffset()!=datetime.timedelta(0):raise ValueError('UTC required')
        if ended or (not records and kind!='start'):raise ValueError('Journal lifecycle')
        if kind=='start' and (records or r['round']!=0 or target!='all'):raise ValueError('Duplicate/invalid start')
        if kind=='tcp-open' and (rounds or active is not None or r['round']!=0):raise ValueError('Late connection')
        if kind=='end':
            if r['status']!='cancelled' and (active is not None or r['round']!=len(rounds)):raise ValueError('Premature end')
            ended=True
        if kind=='round-start':
            if active is not None or r['round']!=len(rounds)+1: raise ValueError('Round gap')
            active=r['round']; attempts=set(); results=set(); round_start=r
        elif kind in ('attempt','result'):
            if active!=r['round'] or target not in TARGETS: raise ValueError('Unexpected challenge')
            seen=attempts if kind=='attempt' else results
            if target in seen or (kind=='result' and target not in attempts): raise ValueError('Challenge order')
            seen.add(target)
        elif kind=='round-complete':
            if active!=r['round'] or attempts!=TARGETS or results!=TARGETS: raise ValueError('Incomplete round')
            rounds.append(dict(round=active,startSequence=round_start['sequence'],startTicks=round_start['ticks'],sequence=r['sequence'],ticks=r['ticks']));active=None
        elif kind not in ('start','tcp-open','end','socket-open','socket-close','post-arm-fence','measurement-end'): raise ValueError('Unknown record kind')
        if kind in ('socket-open','post-arm-fence') and (active is not None or r['round']!=len(rounds)): raise ValueError('Lifecycle inside round')
        records.append(r)
    if any(r['kind']=='socket-open' for r in records):
        from preexisting import continuity
        continuity(records, nonce, terminal=ended)
    return dict(records=records,rounds=rounds,partialBytes=len(tail),partialSHA256=hashlib.sha256(tail).hexdigest(),completeBytes=end)

class Progress:
    def __init__(self): self.ready=False; self.failure=None; self.last=None; self.changed=None; self.prefix=b''
    def observe(self,data,nonce,identity,now):
        if self.failure: raise ValueError(self.failure)
        try:
            value=snapshot(data,nonce,identity)
            if not data.startswith(self.prefix): raise ValueError('Journal changed or truncated')
            self.prefix=data[:value['completeBytes']]
            count=len(value['records'])
            if count!=self.last: self.changed=now; self.last=count
            if self.ready and now-self.changed>8: raise ValueError('Stalled complete records')
            if value['rounds']: self.ready=True
            return value
        except Exception as exc:
            if self.ready: self.failure=str(exc)
            raise
    def fail(self,reason):
        if self.ready: self.failure=reason
        raise ValueError(reason)
