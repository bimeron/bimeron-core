import json,time,sys,pathlib,hashlib,os
nonce=sys.argv[1] if len(sys.argv)>1 else ''
clock=dict(utc=time.time(),mono=time.monotonic(),increment=time.clock_getres(time.CLOCK_REALTIME))
if not nonce:print(json.dumps(clock));raise SystemExit
if len(nonce)!=64 or any(c not in '0123456789abcdef' for c in nonce):raise ValueError('nonce')
r=pathlib.Path('/var/lib/step8')/('run-'+nonce)
h=json.loads((r/'health.json').read_text());i=json.loads((r/'identity.json').read_text())
p=pathlib.Path('/proc')/str(i['pid']);stat=(p/'stat').read_text().rsplit(')',1)[1].split()
live=dict(pid=i['pid'],start=stat[19],boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),command=hashlib.sha256((p/'cmdline').read_bytes()).hexdigest())
print(json.dumps(dict(clock=clock,health=h,identity=i,live=live,zombie=stat[0]=='Z',pcapSize=(r/'ingress.pcap').stat().st_size)))
