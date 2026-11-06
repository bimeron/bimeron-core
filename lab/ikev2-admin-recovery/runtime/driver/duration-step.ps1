param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][ValidateSet('baseline','update','updated','restore','restored','failure-readback')][string]$Stage)
$ErrorActionPreference='Stop';. "$PSScriptRoot/duration-common.ps1"
if($env:COMPUTERNAME -cne '<LAB_GUEST_NAME>'){throw 'Dedicated VM identity mismatch'}
try {
 if($Stage -in @('update','restore')){
  $baseline=Get-Content -Raw "$Root/baseline.json"|ConvertFrom-Json
  $current=Get-DurationSnapshot
  $before=if($Stage -eq 'update'){'PT3M'}else{'PT20M'}
  Assert-DurationSnapshot $baseline $current $before
  $task=Get-ScheduledTask -TaskPath '\' -TaskName 'BimeronStep8Probe' -ErrorAction Stop
  $clone=[Microsoft.Management.Infrastructure.CimInstance]::new($task.Settings)
  if((Get-DurationSettings $clone) -cne (Get-DurationSettings $task.Settings)){throw 'CIM clone changed settings'}
  $clone.ExecutionTimeLimit=if($Stage -eq 'update'){'PT20M'}else{'PT3M'}
  if($task.Settings.ExecutionTimeLimit -cne $before){throw 'CIM clone was not detached'}
  Write-DurationJson "$Root/$Stage-intent.json" ([ordered]@{stage=$Stage;before=$current;target=$clone.ExecutionTimeLimit;settings=(Get-DurationSettings $clone)})
  # Sole settings-only mutation for this stage. No task launch or credential parameters.
  $null=Set-ScheduledTask -TaskPath '\' -TaskName 'BimeronStep8Probe' -Settings $clone -ErrorAction Stop
  Write-DurationJson "$Root/$Stage-returned.json" @{returned=$true;utc=[DateTime]::UtcNow.ToString('o')}
 }else{
  $snapshot=Get-DurationSnapshot
  if($Stage -eq 'baseline'){
   $accepted=Get-Content -Raw "$Root/accepted-3216.json"|ConvertFrom-Json
   Assert-ProbeRegistration $accepted.registration $snapshot.registration
   if($snapshot.comDuration -cne 'PT3M' -or $snapshot.cimDuration -cne 'PT3M' -or $snapshot.wrapperSHA256 -cne 'B63893131C6E8AC01ED775AE2808E1FF32D3C3B5A6241F6452E7122185187A30'){throw 'Baseline duration/wrapper'}
   $oldPolicy=Get-Content -Raw "$Root/accepted-policy.json"|ConvertFrom-Json
   $persistent=@($snapshot.policies|Where-Object {$_.Scope -ne 'Process' -and [int]$_.Scope -ne 0})
   $oldPersistent=@($oldPolicy|Where-Object {[int]$_.Scope -ne 0})
   if(($persistent|ConvertTo-Json -Compress) -cne ($oldPersistent|ConvertTo-Json -Compress)){throw 'Persistent execution policy changed'}
  }elseif($Stage -ne 'failure-readback'){
   $baseline=Get-Content -Raw "$Root/baseline.json"|ConvertFrom-Json
   $duration=if($Stage -eq 'updated'){'PT20M'}else{'PT3M'}
   Assert-DurationSnapshot $baseline $snapshot $duration
  }
  if((& 'C:/Windows/System32/rasdial.exe'|Out-String) -notmatch 'No connections'){throw 'RAS not absent'}
  if(@(Get-Process -Name step9-abi-candidate,step8-reviewed-candidate-v2 -ErrorAction SilentlyContinue).Count){throw 'Native owner present'}
  & 'C:/Windows/System32/netsh.exe' wfp show state "file=$Root/$Stage-bfe.xml"|Out-Null;if($LASTEXITCODE){throw 'BFE readback failed'}
  $bfe=[IO.File]::ReadAllText("$Root/$Stage-bfe.xml").ToLowerInvariant()
  $guids=(Get-Content -Raw "$Root/owned-guids.json"|ConvertFrom-Json).guids
  if($guids.Count -ne 22){throw 'GUID inventory'}
  foreach($guid in $guids){if($bfe.Contains($guid.ToLowerInvariant())){throw 'Owned WFP object remains'}}
  Write-DurationJson "$Root/$Stage.json" $snapshot
 }
}catch{Write-DurationJson "$Root/$Stage-error.json" @{exception=$_.Exception.ToString();record=($_|Out-String);utc=[DateTime]::UtcNow.ToString('o')};throw}
