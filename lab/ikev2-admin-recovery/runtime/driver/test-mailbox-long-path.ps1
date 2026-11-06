$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw 'Run this regression with Windows PowerShell 5.'
}
. "$PSScriptRoot/owner-mailbox.ps1"
function Assert-Test([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw $Message }
}
function Assert-Rejected([scriptblock]$Action, [string]$Expected) {
    $caught = $null
    try { & $Action } catch { $caught = $_ }
    Assert-Test ($null -ne $caught) 'Expected rejection did not occur'
    Assert-Test ($caught.Exception.Message.Contains($Expected)) ("Unexpected rejection: " + $caught)
}
# All fixture files stay under the stage, separate from actual transport state.
$stage = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fixture = Join-Path $stage ('lp-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
$leaf = 'supervisor-exit-ready.json'
$padding = 229 - ($fixture.Length + 1 + 1 + $leaf.Length)
Assert-Test ($padding -gt 0) 'Stage path leaves no room for the controlled fixture'
$directory = Join-Path $fixture ('d' * $padding)
$destination = Join-Path $directory $leaf
$oldTemp = $destination + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
$newTemp = Join-Path $directory ('.owner-' + [Guid]::NewGuid().ToString('N') + '.tmp')
Assert-Test ($destination.Length -eq 229) 'Destination length mismatch'
Assert-Test ($oldTemp.Length -eq 266) 'Old temp length mismatch'
Assert-Test ($newTemp.Length -eq 246) 'New temp length mismatch'
Assert-Test ($directory.StartsWith($stage + '\', [StringComparison]::OrdinalIgnoreCase)) 'Fixture escaped stage'
$null = [IO.Directory]::CreateDirectory($directory)
$helperHash = (Get-FileHash -LiteralPath "$PSScriptRoot/owner-mailbox.ps1" -Algorithm SHA256).Hash
$legacyError = $null
try {
    $stream = [IO.File]::Open($oldTemp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $stream.Dispose()
} catch {
    $legacyError = $_.Exception.GetBaseException()
}
Assert-Test ($null -ne $legacyError) 'Legacy long temp unexpectedly succeeded'
Assert-Test ($legacyError -is [IO.DirectoryNotFoundException]) ('Unexpected legacy failure: ' + $legacyError)
$payload = [Text.Encoding]::UTF8.GetBytes('{"fixture":"local-only","seq":2,"ready":true}')
$expectedHash = Get-OwnerSHA256 $payload
Publish-OwnerBytesOnce $destination $payload $fixture
$read = Read-OwnerBytes $destination $payload.Length $fixture
Assert-Test ((Get-OwnerSHA256 $read) -ceq $expectedHash) 'Published hash mismatch'
Assert-Test ([Convert]::ToBase64String($read) -ceq [Convert]::ToBase64String($payload)) 'Published byte mismatch'
$stamp = [IO.File]::GetLastWriteTimeUtc($destination)
1..3 | ForEach-Object { Publish-OwnerBytesOnce $destination $payload $fixture }
Assert-Test ([IO.File]::GetLastWriteTimeUtc($destination) -eq $stamp) 'Duplicate rewrote destination'
$different = [byte[]]$payload.Clone()
$different[0] = 0
Assert-Rejected { Publish-OwnerBytesOnce $destination $different $fixture } 'Immutable publication conflict'
Assert-Rejected { Publish-OwnerBytesOnce $destination ([byte[]](1)) $fixture } 'Immutable publication conflict'
Assert-Rejected { Read-OwnerBytes $destination ($payload.Length - 1) $fixture } 'Owner file exceeds bound'
Assert-Rejected { Publish-OwnerBytesOnce $destination $payload ($fixture + '-other') } 'Path outside owner root'
Assert-Rejected { Publish-OwnerBytesOnce (Join-Path $directory ('..\' + $leaf)) $payload $fixture } 'Unsafe owner path'
Assert-Rejected { Publish-OwnerBytesOnce $destination $payload $fixture ($payload.Length - 1) } 'Invalid publication size'
Assert-Test ((Get-OwnerSHA256 (Read-OwnerBytes $destination $payload.Length $fixture)) -ceq $expectedHash) 'Conflict changed destination hash'
Assert-Test ([IO.File]::GetLastWriteTimeUtc($destination) -eq $stamp) 'Conflict rewrote destination'
Assert-Test (@(Get-ChildItem -LiteralPath $fixture -Recurse -Force -Filter '*.tmp').Count -eq 0) 'Temporary publication remnants found'
Assert-Test ((Get-FileHash -LiteralPath "$PSScriptRoot/owner-mailbox.ps1" -Algorithm SHA256).Hash -ceq $helperHash) 'Helper changed during test'
[pscustomobject]@{
    result = 'PASS'
    powershell = $PSVersionTable.PSVersion.ToString()
    fixture = $fixture
    destinationLength = $destination.Length
    legacyTempLength = $oldTemp.Length
    correctedTempLength = $newTemp.Length
    legacyFailure = $legacyError.GetType().FullName
    helperSHA256 = $helperHash.ToLowerInvariant()
    payloadSHA256 = $expectedHash
    duplicates = 3
    conflicts = 2
    tempRemnants = 0
} | ConvertTo-Json
