"""Explicit challenge inventory for coordinator review; never grants PASS."""
from records import snapshot,TARGETS
def inventory(data,nonce,identity,barrier_sequence):
 value=snapshot(data,nonce,identity)
 rounds=[r for r in value['rounds'] if r['startSequence']>barrier_sequence]
 rows=[]
 for round in rounds:
  records=[r for r in value['records'] if r['round']==round['round'] and r['kind']=='result']
  rows.append(dict(**round,challenges={r['target']:r['status'] for r in records},unavailable=[r['target'] for r in records if 'unavailable' in r['status']]))
 from preexisting import continuity
 fence=continuity(value['records'],nonce) if any(r['kind']=='socket-open' for r in value['records']) else None
 return dict(status='INCONCLUSIVE',postArmFence=fence,rounds=rows,requiredTargets=sorted(TARGETS),partialBytes=value['partialBytes'],threeCompleteRounds=len(rows)>=3,limitations=['Coordinator must establish measured interval, >=10s span, ingress delivery controls, BFE agreement, full identity/capture continuity and forbidden-escape assessment.'])
