$ErrorActionPreference = 'Stop'
if (-not $env:ANDROID_HOME) { throw 'Set ANDROID_HOME to the Android SDK directory.' }
if (-not $env:ANDROID_NDK_HOME) { throw 'Set ANDROID_NDK_HOME to an installed Android NDK directory.' }
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $output = Join-Path $root 'dist/android'
    New-Item -ItemType Directory -Force $output | Out-Null
    $buildFlags = @()
    $version = $env:BIMERON_VERSION
    if (-not $version) { $version = git describe --tags --abbrev=0 --match 'v[0-9]*' 2>$null; if ($LASTEXITCODE -eq 0) { $version += '-dev' } }
    if ($version) { $buildFlags = @('-ldflags', "-X bimeron/core.Version=$($version.TrimStart('v'))") }
    gomobile bind @buildFlags '-target=android/arm,android/arm64,android/386,android/amd64' '-androidapi=23' '-javapkg=org.bimeron.core' -o (Join-Path $output 'bimeron-core.aar') ./androidcore
    if ($LASTEXITCODE -ne 0) { throw 'Android AAR build failed.' }
    Copy-Item -LiteralPath (Join-Path $root 'LICENSE'), (Join-Path $root 'THIRD_PARTY_NOTICES.txt') -Destination $output -Force
    Write-Output "Prepared $output"
} finally {
    Pop-Location
}
