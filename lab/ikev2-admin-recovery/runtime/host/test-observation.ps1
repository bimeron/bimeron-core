# Offline: extract only the observation statement; never load publisher or native helpers.
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Windows PowerShell 5.1 required'}
# Single-quoted match avoids variable interpolation.
$line=@(Get-Content "$PSScriptRoot/publish-live.ps1" | Where-Object {$_ -like '*if($status.State*'})
if($line.Count -ne 1){throw 'Observation statement missing'}
$predicate=[scriptblock]::Create($line[0])
$count=0
foreach($case in @('null','[]','["error"]','[null]','""','"error"','true','false','{}','0')) {
 $status=ConvertFrom-Json ('{"State":"OBSERVING","Completed300":true,"Errors":'+$case+'}')
 $accepted=$true
 try {& $predicate} catch {$accepted=$false}
 if($accepted -ne ($case -in @('null','[]'))){throw "Predicate regression: $case"}
 $count++
}
foreach($json in @('{"State":"CLOSED","Completed300":true,"Errors":null}','{"State":"OBSERVING","Completed300":false,"Errors":null}','{"State":"OBSERVING","Completed300":true}')) {
 $status=ConvertFrom-Json $json;$accepted=$true
 try {& $predicate} catch {$accepted=$false}
 if($accepted){throw 'Observation gate regression'}
 $count++
}
Write-Output "PASS: $count offline observation cases; Windows PowerShell $($PSVersionTable.PSVersion)"
