param([string]$Stage,[string]$Root,[string]$Nonce,[string]$Artifact,[string]$Digest)
$ErrorActionPreference='Stop'
$null='{}'|ConvertFrom-Json # Load Utility before installing fixture doubles.
$global:ExpectedFixtureRoot=$Root
. "$PSScriptRoot/file-sha256.ps1"
# Local test doubles only: retained guest image observations, never native Scheduler.
$global:ProbeFixtureRoot=$Root
function Get-AuthenticodeSignature([string]$Path){[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=Microsoft Windows, fixture'}}}
function New-Object {
 param([Parameter(Position=0)][string]$TypeName,[Parameter(Position=1)][object[]]$ArgumentList,[string]$ComObject)
 if($ComObject){[IO.File]::WriteAllText("$global:ExpectedFixtureRoot/forbidden-com-reached.txt",$ComObject);throw 'Local fixture forbids all COM creation'}
 Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList
}
if($Stage -eq 'export'){
 & "$Root/export-expected.ps1" -Root $Root -Nonce $Nonce -SmokeOnly -FixtureRegistrationPath "$Root/fixture-registration.json"
}elseif($Stage -eq 'transport'){
 $wire=[Management.Automation.PSSerializer]::Serialize([IO.File]::ReadAllBytes("$Root/smoke-expected.json"))
 [IO.File]::WriteAllText("$Root/transport.clixml",$wire)
 $bytes=[byte[]][Management.Automation.PSSerializer]::Deserialize($wire)
 [IO.File]::WriteAllBytes($Artifact,$bytes)
 [Console]::WriteLine((Get-ProbeFileSHA256 $Artifact))
}elseif($Stage -eq 'inspect'){
 & "$Root/inspect-producer.ps1" -Root "$Root/logs" -Nonce $Nonce -ExpectedPath $Artifact -ExpectedSHA256 $Digest -SmokeOnly -LocalFixture
}elseif($Stage -eq 'reject'){
 # Exercise the actual launch entry; test guard makes any COM reach an explicit failure.
 & "$Root/inspect-producer.ps1" -Root "$Root/logs" -Nonce $Nonce -ExpectedPath $Artifact -ExpectedSHA256 $Digest -LaunchOnce
}else{throw 'Unknown fixture stage'}
