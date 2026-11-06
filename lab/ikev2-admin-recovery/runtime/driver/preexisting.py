"""Narrow retained UDP schema; pure offline predicates, no execution authority."""
import hashlib
import json
import re
import collections

EXACT = {f'carrier/<LAB_PUBLIC_IP>/{p}' for p in (500, 4500)}

def need(v, message):
    if not v: raise ValueError(message)

def sha(b): return hashlib.sha256(b).hexdigest()

def payload(nonce, phase, measurement, socket_id, port, round_number):
    return f'C1PE|{nonce}|{phase}|{measurement}|{socket_id}|{port}|{round_number}'.encode('ascii')

def decode_payload(raw, nonce):
    match = re.fullmatch(rb'C1PE\|([a-f0-9]{64})\|(PRE|TRANSITION|POST)\|(-|[a-f0-9]{64})\|([a-f0-9]{64}-(?:500|4500))\|(500|4500)\|([1-9][0-9]{0,9})', raw)
    if not match or match[1].decode() != nonce: return None
    n, phase, measurement, sid, port, rnd = [x.decode() for x in match.groups()]
    if sid != n+'-'+port or ((phase == 'POST') != (measurement != '-')) or measurement == n: return None
    return dict(phase=phase, measurementNonce=measurement, id=sid, port=int(port), round=int(rnd))

def continuity(records, nonce, terminal=False):
    opened = {}; closed = set(); fence = None; ended = False; transitioned = False; attempts = {}
    for r in records:
        kind, target = r['kind'], r['target']
        if kind == 'socket-open':
            need(target in EXACT and target not in opened and r['round']==0 and r['status']=='connected', 'Replacement or late exact socket')
            d=r['detail']; port=int(target.rsplit('/',1)[1])
            need(set(d)=={'id','handle','local','remote','family','type','protocol','exclusive','session'}, 'Socket schema')
            need(d['id']==nonce+'-'+str(port) and re.fullmatch('[0-9]+',d['handle']) and int(d['handle'])>0, 'Socket identity')
            need(d['local']==f'192.0.2.2:{port}' and d['remote']==f'<LAB_PUBLIC_IP>:{port}', 'Changed exact peer')
            need((d['family'],d['type'],d['protocol'],d['exclusive'])==('InterNetwork','Dgram','Udp',True) and type(d['session']) is int and d['session']>=0, 'Socket properties')
            need(all(d['handle']!=v['handle'] for v in opened.values()), 'Handle alias')
            opened[target]=d
        elif kind == 'post-arm-fence':
            need(fence is None and set(opened)==EXACT and not closed and not ended and target=='all' and r['status']=='consumed', 'Duplicate or late fence')
            d=r['detail']; need(set(d)=={'challengeSHA256','requestId','measurementNonce','frequency','sockets'}, 'Fence schema')
            need(re.fullmatch('[a-f0-9]{64}',d['measurementNonce']) and d['measurementNonce']!=nonce and re.fullmatch('[a-f0-9]{64}',d['challengeSHA256']) and re.fullmatch('[a-f0-9]{32}',d['requestId']), 'Fence nonce/hash')
            need(d['frequency']==json.loads(records[0]['status'])['frequency'] and d['frequency']>0, 'Fence frequency')
            need(sorted(d['sockets'],key=lambda x:x['id'])==sorted(opened.values(),key=lambda x:x['id']), 'Fence sockets')
            fence=r
        elif target in EXACT and kind in ('attempt','result'):
            need(target in opened and not closed and not ended, 'Use outside socket lifetime')
            d=r['detail']; fields={'socket','phase','measurementNonce'} | ({'bytes','socketError'} if kind=='result' else set())
            need(set(d)==fields and d['socket']==opened[target], 'Socket continuity/replacement')
            need(d['phase'] in ('PRE','TRANSITION','POST'), 'Payload phase')
            need(d['measurementNonce']==(fence['detail']['measurementNonce'] if fence else '-') and (d['phase']=='POST')==bool(fence), 'Early/stale nonce')
            if d['phase']=='TRANSITION': transitioned=True
            need(not transitioned or d['phase']!='PRE','PRE after transition')
            if kind=='attempt':
                need(r['status']=='preexisting-connected-send','Exact operation')
                attempts[(r['round'],target)]={k:d[k] for k in ('socket','phase','measurementNonce')}
            else:
                need(attempts.get((r['round'],target))=={k:d[k] for k in ('socket','phase','measurementNonce')},'Result differs from attempt')
                need(type(d['bytes']) is int and d['bytes']>=0 and type(d['socketError']) is int, 'Numeric send evidence')
                if d['socketError']==0:
                    expected=len(payload(nonce,d['phase'],d['measurementNonce'],d['socket']['id'],int(target.rsplit('/',1)[1]),r['round']))
                    need(d['bytes']==expected and r['status']==f"sent:{expected} local={d['socket']['local']}", 'Short/unproved send')
                else: need(d['bytes']==0 and r['status']==f"send-error:{d['socketError']}", 'Socket error evidence')
        elif kind=='measurement-end':
            need(not ended and target=='all' and r['status'] in ('complete','cancelled','error'), 'Duplicate/invalid measurement end'); ended=True
        elif kind=='socket-close':
            need(ended and target in opened and target not in closed and r['detail']==opened[target] and r['status']=='disposed', 'Socket closure mismatch')
            closed.add(target)
    if terminal: need(ended and closed==EXACT and set(opened)==EXACT, 'Missing socket drain')
    return fence

def validate_fence(raw, records, nonce, pin_raw, policy_hash, ack_raw, owner):
    from records import unique
    c=json.loads(raw,object_pairs_hook=unique)
    need(set(c)=={'schema','nonce','measurementNonce','requestId','producerPinSHA256','policySHA256','ackSHA256','owner','producer'}, 'Challenge schema')
    need(c['schema']=='c1pe-challenge-v1' and c['nonce']==nonce and c['producerPinSHA256']==sha(pin_raw) and c['policySHA256']==policy_hash and c['ackSHA256']==sha(ack_raw) and c['owner']==owner, 'Challenge causal binding')
    need(c['producer']==json.loads(pin_raw)['producer'], 'Challenge process binding')
    fence=continuity(records,nonce)
    need(fence is not None and fence['detail']['challengeSHA256']==sha(raw) and fence['detail']['measurementNonce']==c['measurementNonce'] and fence['detail']['requestId']==c['requestId'], 'Producer challenge receipt')
    need(all(r['kind']!='post-arm-fence' and not (r.get('detail',{}).get('phase')=='POST') for r in records[:fence['sequence']-1]), 'Early fence')
    return fence

def coverage(log, cutoff, targets=None):
    """Natural 900s completion amendment; last measured interval starts at fence."""
    rows=log['records']; fence=continuity(rows,rows[0]['nonce'],terminal=True)
    need(fence and cutoff['sequence']==fence['sequence'] and cutoff['round']==fence['round'], 'Fence cutoff')
    need(rows[-1]['kind']=='end' and rows[-1]['status']=='complete', 'Natural terminal required')
    end=next(r for r in rows if r['kind']=='measurement-end')
    need(end['status']=='complete', 'Measurement truncated')
    frequency=fence['detail']['frequency']; duration=(end['ticks']-fence['ticks'])/frequency
    need(duration>=300,'Short post-fence interval despite native completion')
    rounds=set(range(fence['round']+1,end['round']+1))
    need(rounds=={r['round'] for r in log['rounds'] if r['round']>fence['round']},'Skipped complete round')
    out={}
    for target in sorted(EXACT):
        attempts=[r for r in rows if r['kind']=='attempt' and r['target']==target and r['sequence']>fence['sequence']]
        results=[r for r in rows if r['kind']=='result' and r['target']==target and r['sequence']>fence['sequence']]
        need({r['round'] for r in attempts}=={r['round'] for r in results}==rounds and len(attempts)==len(results)==len(rounds)>=300,'Missing paired exact attempts')
        need(all(a['sequence']<b['sequence'] and a['ticks']<=b['ticks'] for a,b in zip(attempts,results)), 'Attempt/result ordering')
        times=[fence['ticks']]+[r['ticks'] for r in attempts]+[end['ticks']]
        gaps=[(b-a)/frequency for a,b in zip(times,times[1:])]
        need(all(0<=g<=8 for g in gaps),'Exact attempt gap or boundary')
        out[target]=dict(attempts=len(attempts),maxGapSeconds=max(gaps),results=dict(collections.Counter(r['status'] for r in results)),socket=attempts[0]['detail']['socket'])
    return out,duration

def exact_hits(parsed, records, nonce, cutoff=None):
    """Extract definite escapes before unrelated parser/counter/coverage checks."""
    attempts={(r['round'],r['target']):r for r in records if r['kind']=='attempt'}
    hits=[]
    for p in parsed['records']:
        d=decode_payload(bytes.fromhex(p['payloadHex']),nonce)
        if not d: continue
        target=f"carrier/<LAB_PUBLIC_IP>/{d['port']}"; a=attempts.get((d['round'],target))
        if not a or p['protocol']!=17 or (p['src'],p['dst'],p['sport'],p['dport'])!=('192.0.2.2','<LAB_PUBLIC_IP>',d['port'],d['port']): continue
        detail=a.get('detail',{})
        if detail.get('socket',{}).get('id')!=d['id'] or detail.get('phase')!=d['phase'] or detail.get('measurementNonce')!=d['measurementNonce']:continue
        if cutoff and (d['phase']!='POST' or a['sequence']<=cutoff['sequence'] or d['round']<=cutoff['round']):continue
        if not cutoff and (d['phase']!='PRE' or not any(r['kind']=='result' and r['round']==d['round'] and r['target']==target and r['status'].startswith('sent:') for r in records)):continue
        hits.append(dict(packet=p,target=target,round=d['round'],attemptSequence=a['sequence']))
    return hits
