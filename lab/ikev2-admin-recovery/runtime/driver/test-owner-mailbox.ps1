$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/owner-mailbox.ps1"
function Bytes([string]$s) { return [Text.Encoding]::UTF8.GetBytes($s) }
function Reject([string]$s) {
    $rejected = $false
    try { $null = Assert-StrictOwnerJson (Bytes $s) } catch { $rejected = $true }
    if (!$rejected) { throw "Accepted invalid JSON: $s" }
}
foreach ($s in @('{"x":1,"x":2}', '{"x":1,"\u0078":2}', '{"a":{"x":1,"x":2}}', '[1,]', '{"a":01}', 'true false', '1e999', "`u{FEFF}{}", '{/*x*/}')) { Reject $s }
$null = Assert-StrictOwnerJson (Bytes '{"x":[null,true,false,-1.2e3,{"x":"escaped\\text"}]}')
$n = 'a' * 64; $c = 'b' * 64
$envelope = '{"schema":"full300-owner-command-v1","nonce":"' + $n + '","configSHA256":"' + $c + '","seq":1,"op":"sample","body":{}}'
$null = Assert-OwnerEnvelope (Bytes $envelope) $n $c 1
if ((Get-OwnerSHA256 (Bytes 'abc')) -cne 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') { throw 'Hash mismatch' }
Write-Output 'Owner mailbox validation tests passed'
function MustReject([scriptblock]$Action) {
    $failed = $false
    try { & $Action } catch { $failed = $true }
    if (!$failed) { throw 'Expected rejection' }
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('owner-mailbox-' + [Guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory((Join-Path $root 'transport/proofs'))
try {
    $path = Join-Path $root 'transport/proofs/admission.json'
    $payload = [byte[]](0,255,13,10,42)
    Publish-OwnerBytesOnce $path $payload $root
    Publish-OwnerBytesOnce $path $payload $root
    $read = Read-OwnerBytes $path 5 $root
    if ([Convert]::ToBase64String($read) -cne [Convert]::ToBase64String($payload)) { throw 'Byte mismatch' }
    MustReject { Publish-OwnerBytesOnce $path ([byte[]](1)) $root }
    MustReject { Read-OwnerBytes $path 4 $root }
    MustReject { Read-OwnerBytes $path 5 (Join-Path $root 'other') }
    $ref = [pscustomobject]@{name='admission.json';sha256=(Get-OwnerSHA256 $payload);length=5}
    Assert-OwnerRefs $ref $root
    $ref.length=4
    MustReject { Assert-OwnerRefs $ref $root }
    $ref.length=5; $ref.sha256='a'*64
    MustReject { Assert-OwnerRefs $ref $root }
    $ref.name='unknown.json'
    MustReject { Assert-OwnerRefs $ref }
    $empty = Join-Path $root 'empty.json'
    Publish-OwnerBytesOnce $empty ([byte[]]@()) $root
    if ((Read-OwnerBytes $empty 0 $root).Length -ne 0) { throw 'Empty read failed' }
    $link = Join-Path $root 'linked.json'
    $null = New-Item -ItemType HardLink -Path $link -Target $path
    MustReject { Read-OwnerBytes $link 10 $root }
    MustReject { Publish-OwnerBytesOnce $path $payload $root }
} finally {
    # Delete only the exclusive temporary fixture directory, never the workspace.
    if ([IO.Path]::GetFullPath($root).StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
Write-Output 'Owner mailbox local file tests passed'
