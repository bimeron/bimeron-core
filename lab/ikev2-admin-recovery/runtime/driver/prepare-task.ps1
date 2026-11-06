param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$Nonce,[ValidateSet('provenance')][string]$Mode='provenance',[ValidateRange(5,900)][int]$ProducerSeconds=45,[ValidateSet('PT3M','PT20M')][string]$TaskDuration='PT3M',[string]$ControlPath)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/file-sha256.ps1"
. "$PSScriptRoot/cancellation.ps1"
# The admitted private run root, bound by its run-identity.json; no name template.
$ControlPath=Resolve-ProbeControlRoot $PSScriptRoot $ControlPath $Nonce
$sourceSHA=(Get-ProbeFileSHA256 $PSCommandPath).ToLowerInvariant()
if($sourceSHA -cne (Get-ProbeFileSHA256 "$ControlPath/preparation-source.ps1").ToLowerInvariant()){throw 'Preparation source freeze mismatch'}
$hostProcess=[Diagnostics.Process]::GetCurrentProcess()
$hostIdentity=@{pid=$PID;creationFileTime=$hostProcess.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()}
$baselineRaw=$null;$deploymentAttempted=$false;$wrapperMutationAttempted=$false;$inspectorLaunchAttempted=$false;$earlyReleased=$false
$outcome=@{schema=1;nonce=$Nonce;inspectorExited=$true;producerExitVerified=$false;exitVerified=$false;taskClosureVerified=$false;launchNeverOccurred=$true;restored=$false;holdReason=$null}
$controlSession=$null;$inspectorJob=$null
function Get-PreparationEarlyState([string]$nonce) {
 # Runs through the existing session. Only exact raw readback; no task Run,
 # deployment, provenance import, inspector, process lookup or policy change.
 $svc=New-Object -ComObject Schedule.Service;$svc.Connect();$task=$svc.GetFolder('\').GetTask('BimeronStep8Probe')
 $policy=Get-ExecutionPolicy -List|Select-Object Scope,ExecutionPolicy|ConvertTo-Json -Compress
 @{schema='full300-early-state-v1';nonce=$nonce;
   task=@{path=[string]$task.Path;xml=[string]$task.Xml;security=[string]$task.GetSecurityDescriptor(7);state=[int]$task.State;instanceGuids=@($task.GetInstances(0)|ForEach-Object {[string]$_.InstanceGuid})};
   wrapper=[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:/BimeronStep8/probe.ps1'));
   policy=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($policy))}|ConvertTo-Json -Depth 8 -Compress
}
function Assert-PreparationEarlyState([string]$Before,[string]$After) {
 $b=$Before|ConvertFrom-Json;$a=$After|ConvertFrom-Json
 if($b.schema -cne 'full300-early-state-v1' -or $a.schema -cne $b.schema -or $b.nonce -cne $Nonce -or $a.nonce -cne $Nonce){throw 'HOLD: early state binding'}
 foreach($v in @($b,$a)){if($v.task.path -cne '\BimeronStep8Probe' -or $v.task.state -ne 3 -or $v.task.instanceGuids.Count -ne 0){throw 'HOLD: ordinary task not exactly idle'}}
 foreach($key in @('path','xml','security')){if(!$b.task.$key -or $b.task.$key -cne $a.task.$key){throw "HOLD: early task $key changed"}}
 foreach($key in @('wrapper','policy')){if(!$b.$key -or $b.$key -cne $a.$key){throw "HOLD: early $key changed"}}
}
function Complete-PreparationEarlyAbort {
 if(!$baselineRaw -or $deploymentAttempted -or $wrapperMutationAttempted -or $inspectorLaunchAttempted -or $changed -or $null -ne $inspectorJob -or $null -ne $controlSession){throw 'HOLD: early branch not sealed before deployment'}
 if([string]$session.State -cne 'Opened' -or [string]$session.Availability -cne 'Available'){throw 'HOLD: original session not idle'}
 $current=Invoke-Command -Session $session -ScriptBlock ${function:Get-PreparationEarlyState} -ArgumentList $Nonce
 Assert-PreparationEarlyState $baselineRaw $current
 $proof=@{schema='full300-early-preparation-v1';nonce=$Nonce;sourceSHA256=$sourceSHA;host=$hostIdentity;
  session=@{instanceId=$session.InstanceId.ToString();state=[string]$session.State;availability=[string]$session.Availability};
  stage='baseline-captured';sealed=$true;deploymentAttempted=$deploymentAttempted;wrapperMutationAttempted=$wrapperMutationAttempted;inspectorLaunchAttempted=$inspectorLaunchAttempted;
  inspectorJob=$null;controlSession=$null;baseline=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($baselineRaw));current=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($current))}
 Publish-ProbeJson "$ControlPath/preparation-early-proof.json" $proof
 # This outcome wakes the controller; it is never itself release authority.
 Publish-PreparationOutcome "$ControlPath/preparation-outcome.json" $outcome
 $timer=[Diagnostics.Stopwatch]::StartNew();$deadlineReported=$false
 while(!(Test-Path -LiteralPath "$ControlPath/preparation-release.json") -or !(Test-Path -LiteralPath "$ControlPath/restore-permit.json")){
  if(!$deadlineReported -and $timer.Elapsed.TotalSeconds -ge 30){
   $deadlineReported=$true;$outcome.holdReason='HOLD: early host release deadline; ownership retained'
   Publish-PreparationOutcome "$ControlPath/preparation-outcome.json" $outcome
  }
  # A deadline never closes the retained session or disarms supervision.
  Start-Sleep -Milliseconds 250
 }
 Assert-ProbeRestorePermit ([IO.File]::ReadAllText("$ControlPath/restore-permit.json")|ConvertFrom-Json) $Nonce
 $release=[IO.File]::ReadAllText("$ControlPath/preparation-release.json")|ConvertFrom-Json
 if((($release.PSObject.Properties.Name|Sort-Object) -join ',') -cne 'cleanupSHA256,earlySHA256,nonce,schema' -or $release.schema -cne 'full300-preparation-release-v1' -or $release.nonce -cne $Nonce -or
  $release.earlySHA256 -cne (Get-ProbeFileSHA256 "$ControlPath/preparation-early-proof.json").ToLowerInvariant() -or $release.cleanupSHA256 -cne (Get-ProbeFileSHA256 "$ControlPath/protected-cleanup.json").ToLowerInvariant()){throw 'HOLD: explicit early release binding'}
 $cleanup=[IO.File]::ReadAllText("$ControlPath/protected-cleanup.json")|ConvertFrom-Json
 if($cleanup.nonce -cne $Nonce -or $cleanup.rasAbsent -ne $true -or $cleanup.ownerAbsent -ne $true -or $cleanup.taskReady -ne $true){throw 'HOLD: protected cleanup prerequisites'}
 $current=Invoke-Command -Session $session -ScriptBlock ${function:Get-PreparationEarlyState} -ArgumentList $Nonce
 Assert-PreparationEarlyState $baselineRaw $current
 # Preserve the same archive/cleanup interface as ordinary restoration, with
 # an honest unchanged-wrapper disposition. Duration restoration remains host-owned.
 Invoke-Command -Session $session -ArgumentList $remote,$baselineRaw -ScriptBlock {param($root,$baseline)
  $before=$baseline|ConvertFrom-Json
  if([Convert]::ToBase64String([IO.File]::ReadAllBytes("$root/original-wrapper.ps1")) -cne $before.wrapper){throw 'HOLD: original wrapper backup changed'}
  @{rasAbsent=$true;ownerAbsent=$true;wrapperRestored=(Get-FileHash 'C:/BimeronStep8/probe.ps1').Hash;taskReady=$true;disposition='verified-unchanged-before-deployment'}|ConvertTo-Json|Set-Content "$root/cleanup.json"
 }
 Copy-Item -FromSession $session -LiteralPath $remote -Destination (Join-Path $local 'guest') -Recurse -ErrorAction Stop
 if([string]$session.State -cne 'Opened' -or [string]$session.Availability -cne 'Available'){throw 'HOLD: session busy before explicit release'}
 $originalSession=$session
 Remove-PSSession -Session $originalSession -ErrorAction Stop
 if(![object]::ReferenceEquals($session,$originalSession) -or [string]$originalSession.State -cne 'Closed'){throw 'HOLD: original session closure unproved'}
 Publish-ProbeJson "$ControlPath/preparation-session-closed.json" @{schema='full300-preparation-session-closed-v1';nonce=$Nonce;host=$hostIdentity;sessionId=$originalSession.InstanceId.ToString();stateBefore='Opened';availabilityBefore='Available';stateAfter=[string]$originalSession.State;releaseSHA256=(Get-ProbeFileSHA256 "$ControlPath/preparation-release.json").ToLowerInvariant()}
}
function Forward-PreparationStop($activeSession){
 $request=Read-ProbeStop "$ControlPath/stop-request.json" $Nonce
 if($request -and $activeSession){
  $effective=Invoke-Command -Session $activeSession -ArgumentList $remote,$Nonce,$request,([IO.File]::ReadAllText("$PSScriptRoot/cancellation.ps1")) -ScriptBlock {
   param($root,$nonce,$request,$helper)
   . ([ScriptBlock]::Create($helper))
   if(Test-Path -LiteralPath $root){$existing=Read-ProbeStop "$root/stop-request.json" $nonce;if($existing){return $existing};try{Publish-ProbeStop "$root/stop-request.json" $request $nonce}catch{if(!(Read-ProbeStop "$root/stop-request.json" $nonce)){throw}};Read-ProbeStop "$root/stop-request.json" $nonce}
  }
  if($effective){return $effective}
 }
 return $request
}
function Assert-PreparationAdmission {
 if(Forward-PreparationStop $session){throw 'Preparation cancelled before next admission stage'}
}
if(Read-ProbeStop "$ControlPath/stop-request.json" $Nonce){
 $outcome.holdReason='Cancelled before setup; no mutation or inspector launch'
 Publish-PreparationOutcome "$ControlPath/preparation-outcome.json" $outcome
 throw $outcome.holdReason
}
$local=Join-Path $ControlPath 'preparation';New-Item -ItemType Directory $local -ErrorAction Stop|Out-Null
# Independently admitted historical input bytes are staged privately by bootstrap.
# No active checkout path is consulted by this fresh-run candidate.
$oldGuids=(Get-Content -Raw "$ControlPath/prior-expected.json"|ConvertFrom-Json).guids
if($oldGuids.Count -ne 22){throw 'Prior owned GUID inventory missing'}
$remote="C:/BimeronStep10Probe/$Nonce";$changed=$false
$cred=Import-Clixml (Join-Path $env:LOCALAPPDATA 'Bimeron/ikev2-clean-lab.credential.xml')
$mutex=[Threading.Mutex]::new($false,'Local\BimeronStep10-<LAB_VM_ID_PREFIX>-session-start');$locked=$false
try{
 $locked=$mutex.WaitOne(3000);if(!$locked){throw 'Session setup mutex timeout'}
 $session=New-PSSession -VMId '<LAB_VM_ID>' -Credential $cred
}finally{if($locked){$mutex.ReleaseMutex()};$mutex.Dispose()}
try{
 Assert-PreparationAdmission
 $baselineRaw=Invoke-Command -Session $session -ArgumentList $remote,$oldGuids,$Nonce,${function:Get-PreparationEarlyState}.ToString() -ScriptBlock {param($root,$oldGuids,$nonce,$readback)
  if($env:COMPUTERNAME -ne '<LAB_GUEST_NAME>'){throw 'VM binding'}
  if((Get-ScheduledTask BimeronStep8Probe).State -ne 'Ready'){throw 'Probe task not ready'}
  if(@(Get-Process -Name step9-abi-candidate,step8-reviewed-candidate-v2 -ErrorAction SilentlyContinue).Count){throw 'Existing native owner'}
  if((& 'C:/Windows/System32/rasdial.exe'|Out-String) -notmatch 'No connections'){throw 'RAS not clean'}
  if((Get-ExecutionPolicy -Scope MachinePolicy) -ne 'Undefined' -or (Get-ExecutionPolicy -Scope UserPolicy) -ne 'Undefined'){throw 'Managed execution policy present'}
  if(@(Get-NetUDPEndpoint -ErrorAction Stop|Where-Object {$_.LocalPort -in @(500,4500)}).Count){throw 'Exact ports must be free before producer startup'}
  foreach($name in @('IKEEXT','PolicyAgent')){if((Get-Service $name).Status -ne 'Stopped'){throw 'IKE services must remain stopped'}}
  New-Item -ItemType Directory $root -ErrorAction Stop|Out-Null
  & 'C:/Windows/System32/netsh.exe' wfp show state "file=$root/preflight-bfe.xml"|Out-Null;if($LASTEXITCODE){throw 'Preflight BFE read failed'}
  $bfe=[IO.File]::ReadAllText("$root/preflight-bfe.xml").ToLowerInvariant()
  foreach($guid in $oldGuids){if($bfe.Contains($guid.ToLowerInvariant())){throw 'Prior owned WFP object present'}}
  Get-ExecutionPolicy -List|Select-Object Scope,ExecutionPolicy|ConvertTo-Json|Set-Content "$root/policy-before.json"
  New-Item -ItemType Directory "$root/logs" -ErrorAction Stop|Out-Null
  & 'C:/Windows/System32/icacls.exe' "$root/logs" /grant 'Step8Probe:(OI)(CI)M'|Out-Null;if($LASTEXITCODE){throw 'Log ACL failed'}
  [IO.File]::WriteAllBytes("$root/original-wrapper.ps1",[IO.File]::ReadAllBytes('C:/BimeronStep8/probe.ps1'))
  (Get-FileHash 'C:/BimeronStep8/probe.ps1').Hash|Set-Content "$root/original-wrapper.sha256"
  Get-ScheduledTask BimeronStep8Probe|ForEach-Object {@{action=@($_.Actions|Select-Object Execute,Arguments,WorkingDirectory);user=$_.Principal.UserId;level=[string]$_.Principal.RunLevel}}|ConvertTo-Json -Depth 4|Set-Content "$root/task-before.json"
  & ([ScriptBlock]::Create($readback)) $nonce
 }
 Assert-PreparationAdmission
 $deploymentAttempted=$true
 foreach($name in @('Journal.cs','ProcessPin.cs','probe.ps1','snapshot.ps1','file-sha256.ps1','inspect-producer.ps1','provenance.ps1','export-expected.ps1','expected-schema.ps1','cancellation.ps1')){Copy-Item -ToSession $session -LiteralPath "$PSScriptRoot/$name" -Destination "$remote/$name"}
 $wrapper="param([int]`$Seconds)`r`n`$ErrorActionPreference='Stop'`r`ntry { & '$remote/probe.ps1' -Nonce '$Nonce' -Seconds $ProducerSeconds -Root '$remote/logs'; exit 0 } catch { [Console]::Error.WriteLine(`$_.Exception.ToString()); exit 1 }`r`n"
 $hash=[Security.Cryptography.SHA256]::Create();try{$wrapperHash=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($wrapper)))).Replace('-','')}finally{$hash.Dispose()}
 $planned=@(@{path='C:/BimeronStep8/probe.ps1';sha256=$wrapperHash})
 Assert-PreparationAdmission
 foreach($name in @('Journal.cs','ProcessPin.cs','probe.ps1','inspect-producer.ps1','provenance.ps1','export-expected.ps1','expected-schema.ps1','snapshot.ps1','file-sha256.ps1','cancellation.ps1')){$planned+=@{path="$remote/$name";sha256=(Get-ProbeFileSHA256 "$PSScriptRoot/$name")}}
 $planned|ConvertTo-Json|Set-Content "$local/planned-inputs.json"
 Copy-Item -ToSession $session -LiteralPath "$local/planned-inputs.json" -Destination "$remote/planned-inputs.json"
 Copy-Item -ToSession $session -LiteralPath "$ControlPath/retained-action.json" -Destination "$remote/retained-action.json"
 Assert-PreparationAdmission
 Invoke-Command -Session $session -ArgumentList $remote,$Nonce,$wrapper,$TaskDuration -ScriptBlock {param($root,$nonce,$wrapper,$taskDuration)
  [IO.File]::WriteAllText("$root/planned-wrapper.ps1",$wrapper,[Text.UTF8Encoding]::new($false))
  $shell='C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
  foreach($stage in @('export','inspect')){
   $args=if($stage -eq 'export'){@('-Root',$root,'-Nonce',$nonce,'-SmokeOnly','-TaskDuration',$taskDuration)}else{@('-Root',"$root/logs",'-Nonce',$nonce,'-ExpectedPath',"$root/smoke-expected.json",'-ExpectedSHA256',(Get-FileHash "$root/smoke-expected.json").Hash,'-SmokeOnly')}
   $script=if($stage -eq 'export'){'export-expected.ps1'}else{'inspect-producer.ps1'}
   $job=Start-Process $shell -WindowStyle Hidden -PassThru -ArgumentList (@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"$root/$script")+$args) -RedirectStandardOutput "$root/smoke-$stage.stdout" -RedirectStandardError "$root/smoke-$stage.stderr"
   $handle=$job.Handle
   if(!$job.WaitForExit(12000) -or $null -eq $job.ExitCode -or $job.ExitCode -ne 0){throw "Pre-mutation $stage smoke failed; no wrapper mutation/Run"}
  }
 }
 Assert-PreparationAdmission
 $wrapperMutationAttempted=$true
 Invoke-Command -Session $session -ArgumentList $wrapper -ScriptBlock {param($wrapper)
  [IO.File]::WriteAllText('C:/BimeronStep8/probe.ps1',$wrapper,[Text.UTF8Encoding]::new($false))
 };$changed=$true
 Assert-PreparationAdmission
 Invoke-Command -Session $session -ArgumentList $remote,$Nonce,$TaskDuration -ScriptBlock {param($root,$nonce,$taskDuration)
  $shell='C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
  $export=Start-Process $shell -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"$root/export-expected.ps1",'-Root',$root,'-Nonce',$nonce,'-TaskDuration',$taskDuration) -RedirectStandardOutput "$root/export.stdout" -RedirectStandardError "$root/export.stderr"
  $handle=$export.Handle;if(!$export.WaitForExit(12000) -or $null -eq $export.ExitCode -or $export.ExitCode -ne 0){throw 'Independent expected export failed; no launch'}
 }
 Copy-Item -FromSession $session -LiteralPath "$remote/expected.json" -Destination "$local/expected-before-launch.json"
 $expectedSHA=(Get-ProbeFileSHA256 "$local/expected-before-launch.json").ToLowerInvariant()
 Assert-PreparationAdmission
 $startupMutex=[Threading.Mutex]::new($false,'Local\BimeronStep10-<LAB_VM_ID_PREFIX>-session-start');$startupLocked=$false
 try{
  $startupLocked=$startupMutex.WaitOne(3000);if(!$startupLocked){throw 'Session setup mutex timeout'}
  $controlSession=New-PSSession -VMId '<LAB_VM_ID>' -Credential $cred
 }finally{if($startupLocked){$startupMutex.ReleaseMutex()};$startupMutex.Dispose()}
 $inspectorLaunchAttempted=$true;$outcome.inspectorExited=$false;$outcome.launchNeverOccurred=$false
 $inspectorJob=Invoke-Command -AsJob -Session $session -ArgumentList $remote,$Nonce,$expectedSHA,$ProducerSeconds,$planned -ScriptBlock {param($root,$nonce,$expectedSHA,$producerSeconds,$plannedInputs)
  $ErrorActionPreference='Stop'
  # PSDirect may be Restricted. Load only the exact helper bytes bound by the
  # host's planned-input ledger, before launching/retaining any inspector.
  # ScriptBlock loading leaves every execution-policy scope unchanged.
  foreach($name in @('cancellation.ps1','file-sha256.ps1')){
   $inputRef=@($plannedInputs|Where-Object {$_.path -ceq "$root/$name"})
   if($inputRef.Count -ne 1 -or $inputRef[0].sha256 -cnotmatch '^[0-9a-fA-F]{64}$'){throw 'Inspector helper source binding missing/ambiguous'}
   $stream=[IO.File]::Open("$root/$name",[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
   try{
    $length=$stream.Length
    if($length -le 0 -or $length -gt 1048576){throw 'Inspector helper source bound'}
    $bytes=[byte[]]::new([int]$length);$offset=0
    while($offset -lt $length){$count=$stream.Read($bytes,$offset,$length-$offset);if(!$count){throw 'Short inspector helper source'};$offset+=$count}
    if($stream.ReadByte() -ne -1 -or $stream.Length -ne $length){throw 'Inspector helper source changed'}
   }finally{$stream.Dispose()}
   $hash=[Security.Cryptography.SHA256]::Create()
   try{$actualSHA=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
   if($actualSHA -cne $inputRef[0].sha256.ToLowerInvariant()){throw 'Inspector helper source hash mismatch'}
   . ([ScriptBlock]::Create(([Text.UTF8Encoding]::new($false,$true)).GetString($bytes)))
  }
  foreach($name in @('Get-ProbeFileSHA256','Read-ProbeStop','Assert-ProbeStop','Publish-ProbeStop','Publish-ProbeJson')){
   $null=Get-Command $name -CommandType Function -ErrorAction Stop
  }
  $actualExpectedSHA=(Get-ProbeFileSHA256 "$root/expected.json").ToLowerInvariant()
  if($actualExpectedSHA -cne $expectedSHA.ToLowerInvariant()){throw 'Inspector expected source hash mismatch'}
  $expectedSHA=$actualExpectedSHA
  $shell='C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
  $inspectorSHA=(Get-ProbeFileSHA256 $shell).ToLowerInvariant()
  $job=Start-Process $shell -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"$root/inspect-producer.ps1",'-Root',"$root/logs",'-Nonce',$nonce,'-Seconds',([string]($producerSeconds+45)),'-ProducerSeconds',([string]$producerSeconds),'-ExpectedPath',"$root/expected.json",'-ExpectedSHA256',$expectedSHA,'-LaunchOnce') -RedirectStandardOutput "$root/inspector-stdout.txt" -RedirectStandardError "$root/inspector-stderr.txt"
  $retainedInspectorHandle=$job.Handle
  $inspectorIdentity=@{pid=$job.Id;creationFileTime=$job.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();path=$shell;sha256=$inspectorSHA}
  $waitHold=$false
  try{
   $wait=[Diagnostics.Stopwatch]::StartNew()
   while(!$job.WaitForExit(250)){
    if($wait.Elapsed.TotalSeconds -gt $producerSeconds+80 -and !$waitHold){
     $waitHold=$true
     'HOLD: retained inspector did not exit'|Set-Content "$root/orchestration-error.txt"
     if(!(Read-ProbeStop "$root/stop-request.json" $nonce)){
      Publish-ProbeStop "$root/stop-request.json" ([pscustomobject]@{schema=1;nonce=$nonce;requestId=[Guid]::NewGuid().ToString('N');reasonCode='inspector-wait-deadline';requestedUtc=[DateTime]::UtcNow.ToString('o')}) $nonce
     }
    }
   }
   Publish-ProbeJson "$root/inspector-exit-proof.json" @{schema='full300-inspector-exit-v1';nonce=$nonce;expectedSHA256=$expectedSHA;inspector=$inspectorIdentity;waitResult='signalled';exitCode=$job.ExitCode;inspectorFinalSHA256=(Get-ProbeFileSHA256 "$root/logs/inspector-final.json").ToLowerInvariant()}
   $job.ExitCode|Set-Content "$root/inspector-exit.txt"
   if($null -eq $job.ExitCode){throw 'Inspector exit missing'}
   if($job.ExitCode -ne 0){throw 'Inspector failed'}
   $info=Get-ScheduledTaskInfo BimeronStep8Probe
   @{result=$info.LastTaskResult;state=[string](Get-ScheduledTask BimeronStep8Probe).State;mode='provenance'}|ConvertTo-Json|Set-Content "$root/task-result.json"
   Copy-Item C:/BimeronStep8Probe/task.txt "$root/task-output.txt"
   if((Get-ScheduledTask BimeronStep8Probe).State -ne 'Ready'){throw 'Task did not exit'}
   if($info.LastTaskResult -ne 0){throw 'Normal wrapper failed'}
  }catch{$_|Out-String|Set-Content "$root/orchestration-error.txt";throw}
 }
 while($inspectorJob.State -in @('Running','NotStarted')){
  $null=Forward-PreparationStop $controlSession
  Start-Sleep -Milliseconds 250
 }
 $inspectorResult=Receive-Job $inspectorJob -ErrorAction SilentlyContinue -ErrorVariable inspectorErrors
 $proof=Invoke-Command -Session $controlSession -ArgumentList $remote -ScriptBlock {param($root)
  if(!(Test-Path "$root/inspector-exit.txt")){throw 'HOLD: inspector exit evidence missing'}
  Get-Content -Raw "$root/logs/inspector-final.json"|ConvertFrom-Json
 }
 if($proof.nonce -cne $Nonce){throw 'HOLD: inspector final nonce mismatch'}
 $outcome.inspectorExited=$true;$outcome.launchNeverOccurred=($proof.launchNeverOccurred -eq $true)
 $outcome.exitVerified=($proof.exitVerified -eq $true);$outcome.producerExitVerified=$outcome.exitVerified
 $outcome.taskClosureVerified=($proof.taskClosureVerified -eq $true)
 if($inspectorErrors -or $proof.failure -or $proof.holdReason){throw "Inspector failed: $($proof.failure) $($proof.holdReason)"}
}catch{$outcome.holdReason=$_.Exception.Message;$_|Out-String|Set-Content "$local/orchestration-error.txt";throw}finally{
 try{
  if($baselineRaw -and !$deploymentAttempted -and !$wrapperMutationAttempted -and !$inspectorLaunchAttempted -and !$changed){
   Complete-PreparationEarlyAbort
   $earlyReleased=$true;$outcome.restored=$true;$outcome.taskClosureVerified=$true
  }
  if($changed){
  if(!$outcome.inspectorExited -or (!$outcome.launchNeverOccurred -and !$outcome.exitVerified)){throw 'HOLD: exact inspector/producer exit unverified; no restoration'}
  if($outcome.launchNeverOccurred){
   $outcome.taskClosureVerified=Invoke-Command -Session $session -ScriptBlock {
    $svc=New-Object -ComObject Schedule.Service;$svc.Connect();$task=$svc.GetFolder('\').GetTask('BimeronStep8Probe')
    ($task.State -eq 3 -and $task.GetInstances(0).Count -eq 0)
   }
  }
  if(!$outcome.taskClosureVerified){throw 'HOLD: task closure unverified before permit'}
  Publish-ProbeJson "$ControlPath/preparation-drain-proof.json" $outcome
  Publish-PreparationOutcome "$ControlPath/preparation-outcome.json" $outcome
  $permitTimer=[Diagnostics.Stopwatch]::StartNew();$permit=$null
  while(!$permit){
   if($permitTimer.Elapsed.TotalSeconds -ge 30 -and !$outcome.holdReason){$outcome.holdReason="HOLD: restore permit deadline; ownership retained";Publish-PreparationOutcome "$ControlPath/preparation-outcome.json" $outcome}
   $null=Forward-PreparationStop $session
   if(Test-Path -LiteralPath "$ControlPath/restore-permit.json"){
    $permit=[IO.File]::ReadAllText("$ControlPath/restore-permit.json")|ConvertFrom-Json
    Assert-ProbeRestorePermit $permit $Nonce
    break
   }
   Start-Sleep -Milliseconds 250
  }
  if(!$permit){throw 'HOLD: host reader drain restore permit absent after 30 seconds'}
  Invoke-Command -Session $session -ArgumentList $remote -ScriptBlock {param($root)
  $deadline=[DateTime]::UtcNow.AddSeconds(45)
  while((Get-ScheduledTask BimeronStep8Probe).State -ne 'Ready' -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 500}
  if((Get-ScheduledTask BimeronStep8Probe).State -ne 'Ready'){throw 'Refusing restore while task active; retain evidence'}
  $svc=New-Object -ComObject Schedule.Service;$svc.Connect();$task=$svc.GetFolder('\').GetTask('BimeronStep8Probe')
  if($task.GetInstances(0).Count){throw 'Task instance remains; refuse restoration'}
  if(Test-Path "$root/logs/provenance-launch.marker"){
   if(!(Test-Path "$root/logs/inspector-final.json")){throw 'Missing retained process exit evidence'}
   $final=Get-Content -Raw "$root/logs/inspector-final.json"|ConvertFrom-Json
   if(@($final.processes|Where-Object {$_.alive}).Count){throw 'Pinned process exit unverified; retain wrapper'}
  }
  if(Test-Path "$root/expected.json"){
   $expected=Get-Content -Raw "$root/expected.json"|ConvertFrom-Json
   if($task.Xml -cne $expected.registration.xml -or $task.GetSecurityDescriptor(7) -cne $expected.registration.security){throw 'Task registration changed'}
   [IO.File]::WriteAllText("$root/registration-after.xml",$task.Xml,[Text.UTF8Encoding]::new($false))
  }
  [IO.File]::WriteAllBytes('C:/BimeronStep8/probe.ps1',[IO.File]::ReadAllBytes("$root/original-wrapper.ps1"))
  $restored=(Get-FileHash 'C:/BimeronStep8/probe.ps1').Hash
  if($restored -ne (Get-Content "$root/original-wrapper.sha256").Trim()){throw 'Wrapper restoration mismatch'}
  $restored|Set-Content "$root/restored.sha256"
  Get-ExecutionPolicy -List|Select-Object Scope,ExecutionPolicy|ConvertTo-Json|Set-Content "$root/policy-after.json"
  $ras=[string](& 'C:/Windows/System32/rasdial.exe'|Out-String)
  $owners=@(Get-Process -Name step9-abi-candidate,step8-reviewed-candidate-v2 -ErrorAction SilentlyContinue)
  if($ras -notmatch 'No connections' -or $owners.Count){throw 'Cleanup not confirmed'}
  & 'C:/Windows/System32/netsh.exe' wfp show state "file=$root/cleanup-bfe.xml"|Out-Null
  if($LASTEXITCODE){throw 'Cleanup BFE readback failed'}
  @{rasAbsent=$true;ownerAbsent=$true;wrapperRestored=$restored;taskReady=$true}|ConvertTo-Json|Set-Content "$root/cleanup.json"
 };$outcome.restored=$true}}catch{$outcome.holdReason=$_.Exception.Message;$_|Out-String|Set-Content "$local/cleanup-error.txt";throw}finally{
  Publish-PreparationOutcome "$ControlPath/preparation-outcome.json" $outcome
  try{if(!$earlyReleased){Copy-Item -FromSession $session -LiteralPath $remote -Destination (Join-Path $local 'guest') -Recurse}}
  catch{$_|Out-String|Set-Content "$local/archive-error.txt";throw}
  finally{
   if($earlyReleased){}elseif($outcome.restored){
    $originalSessions=@($controlSession,$session|Where-Object {$null -ne $_})
    Publish-ProbeJson "$ControlPath/preparation-close-reserved.json" @{nonce=$Nonce;host=$hostIdentity;sessionIds=@($originalSessions|ForEach-Object {$_.InstanceId.ToString()})}
    foreach($originalSession in $originalSessions){
     try{Remove-PSSession -Session $originalSession -ErrorAction Stop}catch{$outcome.holdReason=$_.Exception.Message}
     # No second close attempt; the original object survives uncertain closure.
     while([string]$originalSession.State -cne 'Closed'){Start-Sleep -Milliseconds 250}
    }
    Publish-ProbeJson "$ControlPath/preparation-session-closed.json" @{schema='fresh-preparation-sessions-closed-v1';nonce=$Nonce;host=$hostIdentity;sessions=@($originalSessions|ForEach-Object {@{instanceId=$_.InstanceId.ToString();state=[string]$_.State}})}
   }else{while($true){Start-Sleep -Milliseconds 250}}
  }
 }
}
