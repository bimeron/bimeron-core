param([string]$Nonce,[string]$Mode='provenance')
$ErrorActionPreference='Stop'
[Console]::WriteLine('version='+$PSVersionTable.PSVersion.ToString())
[Console]::WriteLine('exe='+[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
[Console]::WriteLine('autoload='+[string]$PSModuleAutoLoadingPreference)
[Console]::WriteLine('modulepath='+$env:PSModulePath)
# Exercise the local Utility import path used before planned hashes, without credentials/remoting.
$null='{}'|ConvertFrom-Json
foreach($m in @(Get-Module Microsoft.PowerShell.Utility)){[Console]::WriteLine('loaded='+$m.Path+';version='+$m.Version)}
try{$c=Get-Command Get-FileHash -ErrorAction Stop;[Console]::WriteLine('command='+$c.Source+';type='+$c.CommandType)}catch{[Console]::WriteLine('resolution-error='+$_.Exception.Message)}
foreach($m in @(Get-Module -ListAvailable Microsoft.PowerShell.Utility)){[Console]::WriteLine('available='+$m.Path+';version='+$m.Version)}
