$ErrorActionPreference='Stop'
$p=Join-Path $PSScriptRoot 'prep-e8f84d8f803d3459/planned-inputs.json'
$x=Get-Content -Raw $p|ConvertFrom-Json
[Console]::WriteLine('type='+$x.GetType().FullName)
[Console]::WriteLine('members='+[string]::Join(',',@($x.PSObject.Properties.Name)))
@{inputs=$x}|ConvertTo-Json -Depth 5
$y=@($x|ForEach-Object {[ordered]@{path=[string]$_.path;sha256=[string]$_.sha256}})
@{inputs=$y}|ConvertTo-Json -Depth 5
