import hashlib,json,pathlib,subprocess,secrets
b=pathlib.Path(__file__).resolve().parent
out=b/('hash-regression-'+secrets.token_hex(8));out.mkdir()
base=[r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(b/'test-file-sha256.ps1'),'-Nonce','0'*64,'-Mode','provenance']
results=[]
def case(name,path,expected=None,flags=()):
 p=subprocess.run(base+['-Path',str(path)]+list(flags),capture_output=True,timeout=15,env=__import__('windows_powershell').environment())
 (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
 passed=(p.returncode==0 and p.stdout.decode().strip().lower()==expected) if expected else (p.returncode!=0 and not p.stdout.strip())
 results.append(dict(name=name,exit=p.returncode,pass_=passed,path=str(path),expected=expected));assert passed,name
for name,data in [('empty',b''),('abc',b'abc'),('multiblock',bytes(range(256))*1000)]:
 p=out/name;p.write_bytes(data);case(name,p,hashlib.sha256(data).hexdigest());case(name+'-noautoload',p,hashlib.sha256(data).hexdigest(),['-NoAutoload'])
entries=json.loads((b/'freeze-v2/manifest.json').read_text())
for name in ['Journal.cs','ProcessPin.cs','probe.ps1','inspect-producer.ps1','watch-prep.py']:
 e=next(e for e in entries if pathlib.Path(e['Path'])==b/name)
 case('frozen-'+name,b/'freeze-v2'/e['Snapshot'],e['SHA256'])
case('missing',out/'missing');case('unreadable-exclusive-handle',out/'abc',flags=['-Locked'])
case('released-after-error',out/'abc',hashlib.sha256(b'abc').hexdigest())
large=out/'oversize';f=large.open('wb');f.truncate(67108865);f.close();case('oversize',large)
(out/'results.json').write_text(json.dumps(results,indent=2))
print(str(out));print('PASS',len(results))
