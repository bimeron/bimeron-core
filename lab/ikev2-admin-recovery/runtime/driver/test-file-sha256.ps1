param([string]$Nonce,[string]$Mode='provenance',[string]$Path,[switch]$Locked,[switch]$NoAutoload)
$ErrorActionPreference='Stop'
$null='{}'|ConvertFrom-Json
. "$PSScriptRoot/file-sha256.ps1"
if($NoAutoload){$PSModuleAutoLoadingPreference='None'}
$lock=$null
try {
 if($Locked){$lock=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
 [Console]::WriteLine((Get-ProbeFileSHA256 $Path))
}finally{if($lock){$lock.Dispose()}}
