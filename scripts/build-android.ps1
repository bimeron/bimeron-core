$ErrorActionPreference = 'Stop'
if (-not $env:ANDROID_HOME) { throw 'Set ANDROID_HOME to the Android SDK directory.' }
if (-not $env:ANDROID_NDK_HOME) { throw 'Set ANDROID_NDK_HOME to an installed Android NDK directory.' }
$root = Split-Path -Parent $PSScriptRoot
$lock = $null
Push-Location $root
try {
    ./scripts/release-go.ps1
    $dist = New-Item -ItemType Directory -Force (Join-Path $root 'dist')
    # Keep the lock file outside the packaged directory. The handle owns the lock.
    $lock = [IO.File]::Open((Join-Path $dist.FullName '.android-build.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    $output = Join-Path $root 'dist/android'
    New-Item -ItemType Directory -Force $output | Out-Null
    # Keep the NDK install path out of the C/DWARF debug info and, with -trimpath,
    # the source and module cache paths out of the Go code, so the library names no
    # local directory and builds on different hosts match.
    $cflags = if ($env:CGO_CFLAGS) { $env:CGO_CFLAGS } else { '-O2 -g' }
    $env:CGO_CFLAGS = "$cflags -ffile-prefix-map=$($env:ANDROID_NDK_HOME)=/android-ndk"
    $buildFlags = @()
    $version = $env:BIMERON_VERSION
    if (-not $version -and (Get-Command git -ErrorAction SilentlyContinue)) {
        # Windows PowerShell 5.1 turns native stderr into a terminating error
        # under 'Stop'; without a tag, build without a version like the shell
        # script does.
        $global:LASTEXITCODE = 1
        $tag = & { $ErrorActionPreference = 'Continue'; git describe --tags --abbrev=0 --match 'v[0-9]*' 2>$null }
        if ($LASTEXITCODE -eq 0 -and $tag) { $version = "$tag-dev" }
    }
    if ($version) { $buildFlags = @('-ldflags', "-X bimeron/core.Version=$($version.TrimStart('v'))") }
    # gomobile records the absolute directory of this module and of the vendored
    # snapshots in each library's build information. Build from the root of a
    # temporary drive letter mapped to this checkout, so that path names no user
    # or workspace either. A subst mapping belongs to this logon session only.
    $drive = $null
    foreach ($letter in [char[]]'ZYXWVUTSRQPONMLKJIHGFED') {
        if (Test-Path -LiteralPath "${letter}:\") { continue }
        subst "${letter}:" $root | Out-Null
        if ($LASTEXITCODE -eq 0) { $drive = "${letter}:"; break }
    }
    if (-not $drive) { throw 'No free drive letter to map the checkout.' }
    try {
        Push-Location -LiteralPath "$drive\"
        try {
            gomobile bind -trimpath @buildFlags '-target=android/arm,android/arm64,android/386,android/amd64' '-androidapi=23' '-javapkg=org.bimeron.core' -o (Join-Path $output 'bimeron-core.aar') ./androidcore
            if ($LASTEXITCODE -ne 0) { throw 'Android AAR build failed.' }
        } finally {
            Pop-Location
        }
    } finally {
        subst $drive /D | Out-Null
    }
    Copy-Item -LiteralPath (Join-Path $root 'LICENSE'), (Join-Path $root 'THIRD_PARTY_NOTICES.txt') -Destination $output -Force
    Write-Output "Prepared $output"
} finally {
    if ($lock) { $lock.Dispose() }
    Pop-Location
}
