"""Check the independent fixture against a read-only copy of Core85 validation."""
import os, pathlib, shutil, subprocess
base = pathlib.Path(__file__).resolve().parent
source = pathlib.Path('/Users/wrk/.t3/worktrees/bimeron-core/feat-apple-release-manifest/release/applemanifest')
target = base / 'scratch' / 'validator'
target.mkdir(parents=True, exist_ok=True)
shutil.copytree(source, target / 'applemanifest', dirs_exist_ok=True)
(target / 'go.mod').write_text('module provenanceexperiment\n\ngo 1.26.9\n')
shutil.copyfile(base / 'validator-test.go.txt', target / 'applemanifest' / 'independent_test.go')
root = subprocess.check_output(['go', 'env', 'GOROOT'], text=True).strip()
env = dict(os.environ, GOPROXY='off', GOSUMDB='off', GOWORK='off', GOTOOLCHAIN='local', PROVENANCE_SCRATCH=str(base / 'scratch'))
subprocess.run([root + '/bin/go', 'test', './applemanifest', '-run', 'TestIndependentMissingVersionVariable', '-v'], cwd=target, env=env, check=True)
