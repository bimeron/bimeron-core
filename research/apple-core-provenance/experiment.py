"""Offline synthetic builds; never executes generated binaries. Run from repo root."""
import hashlib, json, os, pathlib, shutil, subprocess

base = pathlib.Path('research/apple-core-provenance').resolve()
work = base / 'scratch'
work.mkdir(exist_ok=True)
git = '<LOCAL_HOME>/.local/bin/git'
env = dict(os.environ, GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local', CGO_ENABLED='0', GOCACHE=str(work / 'cache'))
# Resolve installed toolchain without allowing automatic download.
go = subprocess.check_output(['go', 'env', 'GOROOT'], text=True).strip() + '/bin/go'
def run(args, cwd):
    return subprocess.check_output(args, cwd=cwd, env=env, stderr=subprocess.STDOUT, text=True).strip()
a = work / 'checkout-a'
a.mkdir(exist_ok=True)
(a / 'go.mod').write_text('module bimeron\n\ngo 1.26.9\n')
(a / 'main.go').write_text('package main\nimport "fmt"\nvar metadata = "BIMERON_PROVENANCE_V1:0.1.0-beta.1"\nfunc main(){fmt.Println(metadata)}\n')
# Deliberately no core.Version: -X still succeeds, a useful negative control.
if not (a / '.git').exists():
    run([git, 'init', '-q'], a)
    run([git, 'add', '.'], a)
    run([git, '-c', 'user.name=solarcadence', '-c', 'user.email=4gknw59gyj@privaterelay.appleid.com', 'commit', '-qm', 'test: add synthetic provenance fixture'], a)
b = work / 'checkout-b'
if b.exists(): shutil.rmtree(b)
shutil.copytree(a, b)
rows = []
for arch in ('arm64', 'amd64'):
    env['GOOS'], env['GOARCH'] = 'darwin', arch
    for trim in (False, True):
        builds = []
        for root in (a, b):
            out = work / (root.name + '-' + arch + '-' + str(trim))
            args = [go, 'build', '-buildvcs=true'] + (['-trimpath'] if trim else [])
            run(args + ['-ldflags', '-s -w -X bimeron/core.Version=0.1.0-beta.1', '-o', str(out), '.'], root)
            data = out.read_bytes()
            info = run([go, 'version', '-m', str(out)], root)
            assert ('-ldflags=' in info) != trim
            assert 'vcs.modified=false' in info and 'vcs.revision=' in info
            assert 'GOARCH='+arch in info and 'GOOS=darwin' in info
            assert b'BIMERON_PROVENANCE_V1:0.1.0-beta.1' in data
            builds.append((hashlib.sha256(data).hexdigest(), str(root).encode() in data, info))
        rows.append(dict(arch=arch, trimpath=trim, equal_across_paths=builds[0][0]==builds[1][0], checkout_path_present=builds[0][1], sha256=builds[0][0], buildinfo=builds[0][2]))
result = dict(toolchain=run([go, 'version'], a), revision=run([git, 'rev-parse', 'HEAD'], a), rows=rows)
(base / 'results.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps([{k:v for k,v in r.items() if k!='buildinfo'} for r in rows], indent=2))
