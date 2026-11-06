import pathlib,subprocess,json,hashlib,shutil,os
r=pathlib.Path.cwd();b=r/'build/step10-probe';d=b/'freeze-v2';d.mkdir(exist_ok=False);(d/'bytes').mkdir()
go=pathlib.Path(os.environ['USERPROFILE'])/'go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.windows-amd64/bin/go.exe'
env=dict(os.environ,GOTOOLCHAIN='local')
raw=subprocess.check_output([str(go),'list','-deps','-json','./build/step10-probe/source'],text=True,env=env);(d/'go-list-deps.json').write_text(raw)
decoder=json.JSONDecoder();pos=0;paths=set()
while pos<len(raw):
 while pos<len(raw) and raw[pos].isspace():pos+=1
 if pos==len(raw):break
 obj,pos=decoder.raw_decode(raw,pos)
 for key in ['GoFiles','CgoFiles','CFiles','HFiles','SFiles','SysoFiles','EmbedFiles']:
  for name in obj.get(key,[]):paths.add(pathlib.Path(obj['Dir'])/name)
 module=obj.get('Module',{});module=module.get('Replace',module)
 if module.get('GoMod'):paths.add(pathlib.Path(module['GoMod']))
for p in b.rglob('*'):
 if p.is_file() and not any(x.name.startswith('freeze-') for x in p.parents) and '__pycache__' not in p.parts:paths.add(p)
for name in ['go.mod','go.sum','docs/IKEV2_INSTALLATION_CONTRACT.MD','docs/WFP_ABI_READBACK_SPEC.md','core/ikev2_windows.go','internal/killswitch/recovery_windows.go','third_party/wf/layout_windows_test.go','third_party/wf/testdata/fwpm_filter_layout.c','build/step9-abi/source/capture-supervisor.py','build/step9-abi/source/sinks.py','build/step9-abi/freeze-v4/manifest.json','build/step9-abi/run-03402f6d17957406425a2308dcfb9b11006c798ddee8bddc65dbd507ccf3272d/expected.json','build/step9-abi/run-03402f6d17957406425a2308dcfb9b11006c798ddee8bddc65dbd507ccf3272d/final-evidence-manifest.json']:paths.add(r/name)
paths.add(b/'freeze-v1/manifest.json')
review=r/'build/review-step10-independent-0fd5884261034f51823cf9aef74c6298/missing-config'
paths.update(p for p in review.iterdir() if p.is_file())
entries=[]
for i,p in enumerate(sorted(paths,key=str)):
 target=d/'bytes'/('%05d.bin'%i);shutil.copyfile(p,target)
 entries.append(dict(Path=str(p),Snapshot=str(target.relative_to(d)),SHA256=hashlib.sha256(target.read_bytes()).hexdigest()))
(d/'manifest.json').write_text(json.dumps(entries,indent=2))
print('manifest',len(entries),hashlib.sha256((d/'manifest.json').read_bytes()).hexdigest())

old={e['Path']:e['SHA256'] for e in json.loads((b/'freeze-v1/manifest.json').read_text())}
delta=[dict(Path=e['Path'],PreviousSHA256=old.get(e['Path']),SHA256=e['SHA256']) for e in entries if old.get(e['Path'])!=e['SHA256']]
(d/'delta.json').write_text(json.dumps(delta,indent=2))
print('changed existing',[e['Path'] for e in delta if e['PreviousSHA256']])
