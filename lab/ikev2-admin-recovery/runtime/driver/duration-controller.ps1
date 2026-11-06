param([Parameter(Mandatory=$true)][string]$Root,[string]$FixturePath)
$ErrorActionPreference='Stop';. "$PSScriptRoot/duration-common.ps1";. "$PSScriptRoot/duration-wait.ps1"
function Invoke-Step([string]$Stage,[int]$BoundMs){
 $shell='C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
 $p=Start-Process $shell -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"$PSScriptRoot/duration-step.ps1",'-Root',$Root,'-Stage',$Stage) -RedirectStandardOutput "$Root/$Stage.stdout" -RedirectStandardError "$Root/$Stage.stderr"
 $result=Wait-DurationChild $p $BoundMs 30000 "$Root/$Stage-timeout-observation.jsonl"
 Write-DurationJson "$Root/$Stage-process.json" $result
 return $result
}
if($FixturePath){. $FixturePath}
try{
 $baseline=Invoke-Step 'baseline' 10000
 if(!$baseline.restorePermitted){throw 'Baseline failed/timed out; no update'}
 $update=Invoke-Step 'update' 15000
 if($update.timedOut -or !$update.exited){throw 'Update timed out: UNCERTAIN; no restore or cancellation claimed'}
 if($update.exitCode -ne 0){
  $read=Invoke-Step 'failure-readback' 10000
  if(!$read.restorePermitted){throw 'Update failed; readback uncertain'}
  $original=Get-Content -Raw "$Root/baseline.json"|ConvertFrom-Json;$current=Get-Content -Raw "$Root/failure-readback.json"|ConvertFrom-Json
  Assert-DurationSnapshot $original $current 'PT3M'
  Write-DurationJson "$Root/refusal-unchanged.json" @{unchanged=$true;noRestoreNeeded=$true;reason='Settings update failed'}
  throw 'Update failed; original baseline independently unchanged; no restoration needed'
 }
 $updated=Invoke-Step 'updated' 10000
 if(!$updated.restorePermitted){throw 'Updated readback refused: retain state, no blind restore'}
 $restore=Invoke-Step 'restore' 15000
 if(!$restore.restorePermitted){throw 'Restoration failed/timed out: UNCERTAIN'}
 $restored=Invoke-Step 'restored' 10000
 if(!$restored.restorePermitted){throw 'Restoration readback failed/timed out: UNCERTAIN'}
 Write-DurationJson "$Root/result.json" @{status='PASS reversible settings-only duration validation';noTaskLaunch=$true;restored=$true;mask7ExcludesSACL=$true}
}catch{Write-DurationJson "$Root/controller-error.json" @{error=$_.Exception.ToString();record=($_|Out-String)};throw}
