# With no arguments, only check the effective Go release settings.
$ErrorActionPreference = 'Stop'
$settings = go env -u=false -w=false -json=false -changed=false -n=false -x=false GOFLAGS GOEXPERIMENT
if ($LASTEXITCODE -ne 0) { throw 'Could not read Go release settings.' }
if ($settings -join '') { throw 'Unset GOFLAGS and GOEXPERIMENT (also in go env -w).' }
if ($args.Count) {
    go @args
    if ($LASTEXITCODE -ne 0) { throw "Go release command failed ($LASTEXITCODE)." }
}
