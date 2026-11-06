param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop';. "$PSScriptRoot/duration-common.ps1";. "$PSScriptRoot/duration-wait.ps1"
New-Item -ItemType Directory $Output -ErrorAction Stop|Out-Null
$results=@()
function Check([string]$Label,[scriptblock]$Body,[bool]$Reject=$false){
 $errorText=$null;try{& $Body}catch{$errorText=$_.Exception.Message}
 $pass=if($Reject){$null -ne $errorText}else{$null -eq $errorText}
 $script:results+=@{name=$Label;passed=$pass;error=$errorText}
 if(!$pass){throw "Test failed: $Label $errorText"}
}
$original=(Get-Content -Raw "$PSScriptRoot/prep-3216a742d4cccd4f/guest/expected.json"|ConvertFrom-Json).registration.xml
$updated=$original.Replace('<ExecutionTimeLimit>PT3M</ExecutionTimeLimit>','<ExecutionTimeLimit>PT20M</ExecutionTimeLimit>')
Check 'PT20M sole change' {[DurationXml]::EqualExceptDuration($original,$updated,'PT20M')}
Check 'PT3M restore' {[DurationXml]::EqualExceptDuration($original,$original,'PT3M')}
Check 'format whitespace' {[DurationXml]::EqualExceptDuration($original,$updated.Replace('  ','    '),'PT20M')}
$prefix=$updated.Replace('<Task ','<t:Task ').Replace('</Task>','</t:Task>').Replace('xmlns=','xmlns:t=')
# Prefix every element while keeping semantic expanded names.
$prefix=[regex]::Replace($prefix,'<(\/?)(?!t:)([A-Za-z][A-Za-z0-9]*)(?=[ >\/])','<$1t:$2')
Check 'namespace prefix only' {[DurationXml]::EqualExceptDuration($original,$prefix,'PT20M')}
foreach($case in @(
 @('action',$updated.Replace('cmd.exe','other.exe')),
 @('principal',$updated.Replace('1002','1003')),
 @('setting',$updated.Replace('<StopIfGoingOnBatteries>false','<StopIfGoingOnBatteries>true')),
 @('namespace',$updated.Replace('http://schemas.microsoft.com/windows/2004/02/mit/task','urn:wrong')),
 @('duplicate',$updated.Replace('<ExecutionTimeLimit>PT20M</ExecutionTimeLimit>','<ExecutionTimeLimit>PT20M</ExecutionTimeLimit><ExecutionTimeLimit>PT20M</ExecutionTimeLimit>')),
 @('wrong duration',$updated.Replace('PT20M','PT21M')),
 @('missing duration',$updated.Replace('<ExecutionTimeLimit>PT20M</ExecutionTimeLimit>','')),
 @('order',$updated.Replace('<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>','').Replace('<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>','<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>')),
 @('DTD','<!DOCTYPE Task [<!ENTITY x "x">]>'+$updated.Substring($updated.IndexOf('<Task')))
)){$xml=$case[1];Check $case[0] {[DurationXml]::EqualExceptDuration($original,$xml,'PT20M')} $true}
$class=Get-CimClass -Namespace Root/Microsoft/Windows/TaskScheduler -ClassName MSFT_TaskSettings3 -ErrorAction Stop
$settings=New-CimInstance -CimClass $class -ClientOnly -Property @{ExecutionTimeLimit='PT3M';AllowDemandStart=$true;MultipleInstances=[uint32]2}
$clone=[Microsoft.Management.Infrastructure.CimInstance]::new($settings)
Check 'actual CIM clone equality' {if((Get-DurationSettings $clone) -cne (Get-DurationSettings $settings)){throw 'Clone metadata/values differ'}}
$clone.ExecutionTimeLimit='PT20M'
Check 'actual CIM detached mutation' {if($settings.ExecutionTimeLimit -cne 'PT3M' -or $clone.ExecutionTimeLimit -cne 'PT20M'){throw 'Not detached'}}
$old=[pscustomobject]@{registration=[pscustomobject]@{xml=$original;path='\BimeronStep8Probe';security='O:BAG:BAD:(A;;FA;;;BA)';action=@();principal=@{}};settings=(Get-DurationSettings $settings);comDuration='PT3M';cimDuration='PT3M';wrapperSHA256='fixture';securityBinary='fixture';policies=@();taskReady=$true;instances=0}
$cur=($old|ConvertTo-Json -Depth 30|ConvertFrom-Json);$cur.registration.xml=$updated;$cur.settings=Get-DurationSettings $clone;$cur.comDuration='PT20M';$cur.cimDuration='PT20M'
Check 'complete snapshot sole duration' {Assert-DurationSnapshot $old $cur 'PT20M'}
$cur.registration.security='O:BAG:BAD:(A;;FR;;;BA)';Check 'SDDL changed' {Assert-DurationSnapshot $old $cur 'PT20M'} $true;$cur.registration.security=$old.registration.security
$clone.AllowDemandStart=$false;$cur.settings=Get-DurationSettings $clone;Check 'other CIM setting changed' {Assert-DurationSnapshot $old $cur 'PT20M'} $true
[IO.File]::WriteAllText("$Output/process-fixture.ps1",'param([int]$Delay,[int]$Code,[string]$Done);Start-Sleep -Milliseconds $Delay;[IO.File]::WriteAllText($Done,"natural exit");exit $Code')
$shell='C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
foreach($spec in @(@('normal',10,0,5000,1000),@('nonzero',10,23,5000,1000),@('late',500,0,50,3000),@('still-active',1200,0,50,100))){
 $name=$spec[0];$p=Start-Process $shell -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"$Output/process-fixture.ps1",'-Delay',$spec[1],'-Code',$spec[2],'-Done',"$Output/$name.done") -RedirectStandardOutput "$Output/$name.stdout" -RedirectStandardError "$Output/$name.stderr"
 $wait=Wait-DurationChild $p $spec[3] $spec[4] "$Output/$name-heartbeat.jsonl";Write-DurationJson "$Output/$name-result.json" $wait
 Check "$name exit/timeout propagation" {
  if($name -eq 'normal'){if(!$wait.restorePermitted -or $wait.exitCode -ne 0){throw 'Normal failed'}}
  elseif($name -eq 'nonzero'){if($wait.exitCode -ne 23 -or $wait.restorePermitted){throw 'Exit masked'}}
  else{if(!$wait.timedOut -or $wait.restorePermitted){throw 'Timeout reset/restore allowed'}}
  if($name -eq 'still-active' -and $wait.exited){throw 'Did not test live timeout'}
 }
 # No restore dispatch on timeout/error, even after late exit; let the child finish naturally.
 if($wait.restorePermitted){[IO.File]::WriteAllText("$Output/$name.restore",'allowed after exact exit')}
 $null=$p.WaitForExit(5000)
 Check "$name no kill/no overlap" {if(!$p.HasExited -or !(Test-Path "$Output/$name.done")){throw 'Natural completion missing'};if($name -ne 'normal' -and (Test-Path "$Output/$name.restore")){throw 'Forbidden restore'}}
}
Write-DurationJson "$Output/results.json" $results
[Console]::WriteLine("PASS $($results.Count) duration tests")
