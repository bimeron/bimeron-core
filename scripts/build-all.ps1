# Build and package the six Windows, Linux, and macOS CLI targets.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    go run scripts/build-dist.go
    if ($LASTEXITCODE -ne 0) { throw 'Distribution build failed.' }
} finally {
    Pop-Location
}
