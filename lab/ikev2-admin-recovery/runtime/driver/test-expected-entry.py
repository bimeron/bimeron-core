import copy,hashlib,json,pathlib,secrets,shutil,subprocess,os,sys
b=pathlib.Path(__file__).resolve().parent
out=b/('schema-regression-'+secrets.token_hex(8));out.mkdir();(out/'logs').mkdir()
nonce=secrets.token_hex(32);root=out.as_posix()
names=['Journal.cs','ProcessPin.cs','probe.ps1','inspect-producer.ps1','provenance.ps1','export-expected.ps1','expected-schema.ps1','snapshot.ps1','file-sha256.ps1']
for name in names:shutil.copyfile(b/name,out/name)
old=json.loads((b/'prep-e8f84d8f803d3459/expected-before-launch.json').read_text(encoding='utf-8-sig'))
reg=old['registration'];reg['principal']['privileges']=[]
(out/'fixture-registration.json').write_text(json.dumps(reg))
(out/'retained-action.json').write_text(json.dumps(reg['action']))
(out/'planned-wrapper.ps1').write_text('# Local fixture only; never executed\n')
planned=[dict(path='C:/BimeronStep8/probe.ps1',sha256=hashlib.sha256((out/'planned-wrapper.ps1').read_bytes()).hexdigest())]
planned += [dict(path=root+'/'+n,sha256=hashlib.sha256((out/n).read_bytes()).hexdigest()) for n in names]
(out/'planned-inputs.json').write_text(json.dumps(planned))
base=[('pwsh.exe' if '--ps7' in sys.argv else r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'),'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(b/'test-expected-entry.ps1'),'-Root',root,'-Nonce',nonce]
results=[]
import windows_powershell
env=windows_powershell.pwsh_environment() if '--ps7' in sys.argv else windows_powershell.environment()
if '--native-modules' in sys.argv:env['PSModulePath']=r'C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
def run(name,stage,artifact=None,digest=None,success=True):
 args=base+['-Stage',('reject' if stage=='inspect' and not success else stage)]
 if artifact:args+=['-Artifact',str(artifact)]
 if digest:args+=['-Digest',digest]
 p=subprocess.run(args,capture_output=True,timeout=15,env=env)
 (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
 good=(p.returncode==0)==success and not (out/'logs/provenance-launch.marker').exists() and not (out/'logs/launch.json').exists() and not (out/'forbidden-com-reached.txt').exists()
 if name=='wronghash':good=good and b'Expected input/image mismatch' in p.stderr
 if name=='missing-dependency':good=good and b'snapshot.ps1' in p.stderr and (b'FileNotFoundException' in p.stderr or b'Could not find file' in p.stderr)
 results.append(dict(name=name,exit=p.returncode,passed=good,noLaunchMarker=True))
 (out/'results.json').write_text(json.dumps(results,indent=2))
 assert good,(name,p.stderr.decode(errors='replace'))
 return p.stdout.decode().strip()
run('actual-export','export')
artifact=out/'host-expected.json';digest=run('clixml-transport-hosthash','transport',artifact)
assert artifact.read_bytes()==(out/'smoke-expected.json').read_bytes()
valid=json.loads(artifact.read_text());assert isinstance(valid['inputs'],list)
run('array-positive','inspect',artifact,digest)
mutations={
 'objectwrapped':lambda x:x.update(inputs=dict(value=x['inputs'],Count=len(x['inputs']))),
 'null':lambda x:x.update(inputs=None),
 'missing':lambda x:x.pop('inputs'),
 'duplicate':lambda x:x['inputs'].__setitem__(1,copy.deepcopy(x['inputs'][0])),
 'wronghash':lambda x:x['inputs'][1].update(sha256='0'*64),
 'wrongpath':lambda x:x['inputs'][1].update(path=root+'/wrong.cs'),
 'emptyhash':lambda x:x['inputs'][1].update(sha256=''),
 'wrongcount':lambda x:x['inputs'].pop(),
 'wrongtype':lambda x:x.update(schemaVersion='1'),
 'wrongimage':lambda x:x['images']['cmd'].update(sha256='0'*64),
 'wrongprincipal':lambda x:x['registration']['principal'].update(level=1),
 'wrongaction':lambda x:x['registration']['action'][0].update(Execute='other.exe'),
}
for name,mutate in mutations.items():
 data=copy.deepcopy(valid);mutate(data);p=out/(name+'.json');p.write_text(json.dumps(data));run(name,'inspect',p,hashlib.sha256(p.read_bytes()).hexdigest(),False)
run('wrong-artifact-hash','inspect',artifact,'0'*64,False)
# A missing deployed dependency must refuse the complete pre-mutation smoke route.
(out/'snapshot.ps1').rename(out/'snapshot-removed.ps1')
run('missing-dependency','inspect',artifact,digest,False)
print(out);print('PASS',len(results))
