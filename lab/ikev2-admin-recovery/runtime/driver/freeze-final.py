"""Final closure evidence snapshot; not a runnable WFP admission bundle."""
import pathlib,json,hashlib,shutil,subprocess,os,sys
if len(sys.argv)!=2 or not pathlib.PureWindowsPath(sys.argv[1]).is_absolute() or sys.argv[1].startswith(('\\','/')):raise SystemExit('usage: freeze-final.py ABSOLUTE-GIT-PATH')
git=sys.argv[1]
r=pathlib.Path.cwd();b=r/'build/step10-probe';dest=b/'final-freeze';dest.mkdir(exist_ok=False);(dest/'bytes').mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
prior=json.loads((b/'freeze-v2/manifest.json').read_text())
production=[]
for e in prior:
 p=pathlib.Path(e['Path'])
 if p.is_relative_to(r) and p.parts[len(r.parts)] not in ('build','docs') and p.is_file():
  production.append(dict(path=str(p),v2=e['SHA256'],current=sha(p),equal=sha(p)==e['SHA256']))
assert all(x['equal'] for x in production),'Production differs from reviewed baseline'
(b/'final-owned-state/production-v2-comparison.json').write_text(json.dumps(production,indent=2))
paths={p for p in b.rglob('*') if p.is_file() and not p.is_relative_to(dest) and '__pycache__' not in p.parts}
paths.update(pathlib.Path(e['Path']) for e in prior if pathlib.Path(e['Path']).is_file())
for command in [[git,'diff','--name-only'],[git,'ls-files','--others','--exclude-standard']]:
 paths.update(r/p for p in subprocess.check_output(command,text=True).splitlines() if (r/p).is_file())
paths.update([r/'AGENTS.md',r/'go.mod',r/'go.sum'])
entries=[]
for p in sorted(paths,key=str):
 # No credential/key stores or remote authentication material can enter this snapshot.
 if 'AppData/Local/Bimeron' in p.as_posix() or p.name.lower().endswith(('.credential.xml','.pem','.key')) or p.name in ('client2','known_hosts2'):
  raise ValueError('Sensitive source path refused')
 data=p.read_bytes();digest=hashlib.sha256(data).hexdigest();target=dest/'bytes'/(digest+'.bin')
 if not target.exists():target.write_bytes(data)
 entries.append(dict(Path=str(p.resolve()),Snapshot=str(target.relative_to(dest)),SHA256=digest,Size=len(data)))
manifest=dest/'manifest.json';manifest.write_text(json.dumps(entries,indent=2))
for e in entries:
 assert sha(dest/e['Snapshot'])==e['SHA256'] and sha(pathlib.Path(e['Path']))==e['SHA256']
for p in dest.rglob('*'):
 if p.is_file():p.chmod(0o444)
print(json.dumps(dict(path=str(manifest.resolve()),count=len(entries),sha256=sha(manifest),uniqueBytes=len(list((dest/'bytes').iterdir())),productionUnchanged=len(production)),indent=2))
