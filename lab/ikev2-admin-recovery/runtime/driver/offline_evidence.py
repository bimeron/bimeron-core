import argparse, hashlib, ipaddress, json, re, struct
from decimal import Decimal
from pathlib import Path
MAX = 64 * 1024 * 1024

def dns_rounds(payload, nonce, tcp):
    if tcp:
        if len(payload)<2 or int.from_bytes(payload[:2],'big')!=len(payload)-2: return []
        payload=payload[2:]
    if len(payload)<12 or payload[:12]!=bytes.fromhex('531001000001000000000000'):return []
    labels=[];pos=12
    while pos<len(payload):
        n=payload[pos];pos+=1
        if n==0:break
        if n>63 or pos+n>len(payload):return []
        labels.append(payload[pos:pos+n]);pos+=n
    if payload[pos:]!=b'\x00\x01\x00\x01' or len(labels)!=5:return []
    if labels[:3]!=[b's10',nonce[:32].encode(),nonce[32:].encode()] or labels[4]!=b'test':return []
    if not re.fullmatch(rb'r[1-9][0-9]{0,9}',labels[3]):return []
    return [labels[3][1:].decode()]

def assess(data, nonce, lower, upper):
    lo, hi = Decimal(lower), Decimal(upper)
    if not re.fullmatch('[0-9a-f]{64}', nonce) or not lo.is_finite() or not hi.is_finite() or lo >= hi:
        raise ValueError('Invalid nonce or finite ordered observer bounds')
    if len(data) > MAX: raise ValueError('Capture exceeds 64 MiB')
    out = dict(status='INCONCLUSIVE', sha256=hashlib.sha256(data).hexdigest(), lower=str(lo), upper=str(hi), records=[], limitations={})
    def limit(reason): out['limitations'][reason] = out['limitations'].get(reason, 0) + 1
    formats = {b'\xd4\xc3\xb2\xa1':('<',1000000), b'\xa1\xb2\xc3\xd4':('>',1000000), b'\x4d\x3c\xb2\xa1':('<',1000000000), b'\xa1\xb2\x3c\x4d':('>',1000000000)}
    if len(data)<24 or data[:4] not in formats:
        limit('truncated_or_unsupported_capture_header'); return out
    e, scale = formats[data[:4]]
    major, minor, _, _, snap, link = struct.unpack(e+'HHIIII',data[4:24])
    if (major,minor)!=(2,4) or link!=1 or not snap:
        limit('unsupported_header_or_framing'); return out
    pos=24; count=0
    while pos<len(data):
        if count>=100000: limit('record_limit'); break
        count+=1
        if pos+16>len(data): limit('truncated_record_header'); break
        sec,frac,n,orig=struct.unpack(e+'IIII',data[pos:pos+16]); pos+=16
        if n>1048576 or n>snap or n>orig or frac>=scale: limit('invalid_record'); break
        if pos+n>len(data): limit('truncated_record'); break
        p=data[pos:pos+n]; pos+=n
        if n<orig: limit('snaplen_truncation'); continue
        try:
            if len(p)<14: raise ValueError('truncated_ethernet')
            kind=struct.unpack('!H',p[12:14])[0]; p=p[14:]
            if kind==0x800:
                if len(p)<20: raise ValueError('truncated_ipv4')
                ihl=(p[0]&15)*4; total=int.from_bytes(p[2:4],'big')
                if p[0]>>4!=4 or ihl<20 or total<ihl or len(p)<total: raise ValueError('invalid_or_truncated_ipv4')
                if int.from_bytes(p[6:8],'big')&0x3fff: raise ValueError('ipv4_fragment')
                src,dst=[str(ipaddress.ip_address(p[x:x+4])) for x in (12,16)]; proto=p[9]; p=p[ihl:total]
            elif kind==0x86dd:
                if len(p)<40: raise ValueError('truncated_ipv6')
                total=40+int.from_bytes(p[4:6],'big')
                if p[0]>>4!=6 or total==40 or len(p)<total: raise ValueError('invalid_or_truncated_ipv6')
                src,dst=[str(ipaddress.ip_address(p[x:x+16])) for x in (8,24)]; proto=p[6]; p=p[40:total]
                if proto not in (6,17): raise ValueError('ipv6_extension_fragment_or_unsupported_protocol')
            else: raise ValueError('unsupported_ethernet_type_including_vlan')
            if proto not in (6,17): raise ValueError('unsupported_transport')
            if len(p)<(8 if proto==17 else 20): raise ValueError('truncated_transport')
            sport,dport=struct.unpack('!HH',p[:4])
            if proto==17:
                end=int.from_bytes(p[4:6],'big'); start=8
                if end<8 or end>len(p): raise ValueError('invalid_udp_length')
            else:
                start=(p[12]>>4)*4; end=len(p)
                if start<20 or start>end: raise ValueError('invalid_tcp_header')
            payload=p[start:end]
            matches=list(re.finditer(rb'STEP8-'+nonce.encode()+rb'-ORDINARY-([0-9]{1,10})(?=STEP8-|$)',payload))
            sequences=[m[1].decode() for m in matches]
            rounds=[m[1].decode() for m in re.finditer(rb'STEP10-'+nonce.encode()+rb'-ROUND-([1-9][0-9]{0,9})-END',payload)]
            from preexisting import decode_payload
            exact=decode_payload(payload,nonce) if proto==17 else None
            if exact: rounds=[str(exact['round'])]
            if dport==53:rounds+=dns_rounds(payload,nonce,proto==6)
            stamp=Decimal(sec)+Decimal(frac)/scale
            phase='inside' if lo<stamp<hi else ('before' if stamp<=lo else 'after')
            target=(dst=='<LAB_PUBLIC_IP>' and proto==17 and dport in (500,4500)) or (dst in ('192.0.2.1','fd42:8::1') and dport in ((8080,53) if proto==6 else (49000,53)))
            forbidden=bool(sequences or rounds) and phase=='inside' and src in ('192.0.2.2','fd42:8::2') and target
            out['records'].append(dict(offset=pos-n,packetSHA256=__import__('hashlib').sha256(data[pos-n:pos]).hexdigest(),payloadHex=payload.hex(),index=count,timestamp=str(stamp),phase=phase,src=src,dst=dst,protocol=proto,sport=sport,dport=dport,sequences=sequences,rounds=rounds,forbidden_candidate=forbidden))
            if forbidden: out['status']='FORBIDDEN_PACKET_CANDIDATES'
        except ValueError as exc: limit(str(exc))
    return out

if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('pcap'); ap.add_argument('--nonce',required=True); ap.add_argument('--lower',required=True); ap.add_argument('--upper',required=True); a=ap.parse_args()
    with Path(a.pcap).open('rb') as f: data=f.read(MAX+1)
    print(json.dumps(assess(data,a.nonce,a.lower,a.upper),indent=2))
