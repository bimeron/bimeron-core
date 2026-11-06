"""Read-only current observer protection check; invoked only operationally."""
import pathlib,sys,subprocess
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'driver'))
from protected_transport import strict,freeze,sha,encode
from live_prepare import ssh_command,partition,canonical,absolute_executable

def verify(proof_path,label):
 p=pathlib.Path(proof_path);base=p.parent;proof=strict(p.read_bytes())
 c=strict((base.parent/'host-supervisor-config.json').read_bytes())
 # The owner-published capture query carries the pinned ssh image.
 raw=subprocess.run(ssh_command('sudo nft -j list ruleset',c['query'][0]),input=b'',capture_output=True,timeout=15,check=True).stdout
 own,other=partition(strict(raw),proof['table'])
 if canonical(own)!=canonical(strict((base/'readback.json').read_bytes())) or canonical(other)!=canonical(strict((base/'before.json').read_bytes())):raise ValueError('Observer guard changed')
 capture_raw=subprocess.run([absolute_executable(c['query'][0],'ssh'),*c['query'][1:]],input=b'',capture_output=True,timeout=6,check=True).stdout
 capture=strict(capture_raw)
 if capture['Healthy'] is not True or capture['LiveIdentityHealthy'] is not True or capture['Identity']!=c['capture']:raise ValueError('Capture changed')
 if label=='recovery':return
 freeze(base/'stock'/('protection-'+label+'.json'),encode(dict(nonce=proof['admission']['Binding']['Nonce'],guardSHA256=sha(canonical(own)),capture=capture)))
if __name__=='__main__':
 if len(sys.argv)!=3 or sys.argv[2] not in ('deployment','permit','recovery'):raise SystemExit(64)
 verify(sys.argv[1],sys.argv[2])
