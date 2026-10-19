param([ValidateSet('amd64','arm64')][string]$Architecture = 'amd64')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    go run scripts/build-dist.go "windows-$Architecture"
    if ($LASTEXITCODE -ne 0) { throw "Wintun package build failed for $Architecture." }
} finally {
    Pop-Location
}
