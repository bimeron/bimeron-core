param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$Nonce,[ValidateRange(1,1200)][int]$Seconds=90,[ValidateRange(5,1800)][int]$ProducerSeconds=45,[Parameter(Mandatory=$true)][string]$ExpectedPath,[Parameter(Mandatory=$true)][string]$ExpectedSHA256,[switch]$LaunchOnce,[switch]$SmokeOnly,[switch]$LocalFixture)
$ErrorActionPreference='Stop';. "$PSScriptRoot/file-sha256.ps1"
if($LocalFixture -and !$SmokeOnly){throw 'Local fixture requires smoke mode; never launch'}
if($LaunchOnce -eq $SmokeOnly){throw 'Exactly one launch or smoke mode required'}
if(!$LaunchOnce -and !$SmokeOnly){throw 'Explicit once-only launch required'}
. "$PSScriptRoot/cancellation.ps1"
. "$PSScriptRoot/provenance.ps1"
. "$PSScriptRoot/expected-schema.ps1"
Add-Type -Path "$PSScriptRoot/ProcessPin.cs";Add-Type -Path "$PSScriptRoot/Journal.cs"
$pins=@();$inputs=@();$ready=$false;$failure=$null;$pinned=$null;$launch=$null;$completed=$false;$healthJournal=$null
$cancelled=$false;$exitVerified=$false;$taskClosureVerified=$false;$launchNeverOccurred=$true;$request=$null;$holdReason=$null;$terminalDecision=$null;$exitBudget=$null
$timer=[Diagnostics.Stopwatch]::StartNew();$lastLength=0;$lastProgress=0
function Facts($pin,$parent){
 $pin.RefreshToken()
 $process=Get-CimInstance Win32_Process -Filter "ProcessId=$($pin.Pid)"
 if(!$process -and !$pin.Alive){throw 'Process exited'}
 if(!$process -or !(Test-ProbeCimCreation $process.CreationDate $pin.Start)){throw 'Pinned process observation missing/reused'}
 @{pid=$pin.Pid;start=$pin.Start;path=$pin.Path;sid=$pin.Sid;integrity=$pin.Integrity;elevated=$pin.Elevated;alive=$pin.Alive;sha256=(Get-ProbeFileSHA256 $pin.Path);parent=$parent;arguments=@([ProcessPin]::Arguments($process.CommandLine))}
}
function Read-FirstProducerRecord([byte[]]$Bytes,$ExpectedProducer,[string]$ExpectedNonce,[string]$DiagnosticRoot) {
 $text=[Text.UTF8Encoding]::new($false,$true).GetString($Bytes)
 $newline=$text.IndexOf("`n")
 if($newline -lt 0){throw 'Waiting for first complete producer record'}
 $raw=$text.Substring(0,$newline);$first=$null;$parseFailure=$null
 try{$first=$raw|ConvertFrom-Json}catch{$parseFailure=$_.Exception.Message}
 $matches=$false
 if(!$parseFailure -and $first){
  try{$matches=($first.kind -ceq 'start' -and $first.nonce -ceq $ExpectedNonce -and $first.producer.pid -eq $ExpectedProducer.pid -and $first.producer.sid -ceq $ExpectedProducer.sid -and [DateTime]::Parse($first.producer.start).ToUniversalTime() -eq [DateTime]::Parse($ExpectedProducer.start).ToUniversalTime())}catch{$parseFailure=$_.Exception.Message}
 }
 if(!$matches){
  $diagnostic=@{nonce=$ExpectedNonce;bytesLength=$Bytes.Length;firstRecord=$first;firstRecordText=$raw;expectedIdentity=@{pid=$ExpectedProducer.pid;start=$ExpectedProducer.start;sid=$ExpectedProducer.sid};parseFailure=$parseFailure}
  try{Publish-ProbeJson (Join-Path $DiagnosticRoot ('m-'+[Guid]::NewGuid().ToString('N').Substring(0,16)+'.json')) $diagnostic}catch{[Console]::Error.WriteLine('Producer mismatch diagnostic publication failed: '+$_.Exception.Message)}
  throw 'Producer report disagrees with independent chain'
 }
 return $first
}
function Read-BoundTerminal {
 $text=[Text.UTF8Encoding]::new($false,$true).GetString([ProbeJournal]::Snapshot("$Root/probe-$Nonce.jsonl"))
 $end=$text.LastIndexOf("`n");if($end -lt 0){throw 'Terminal missing'}
 $rows=@($text.Substring(0,$end).Split("`n")|Where-Object {$_}|ForEach-Object {$_|ConvertFrom-Json})
 Get-ProbeTerminalDecision $rows $pinned.producer $Nonce $ProducerSeconds (Read-ProbeStop "$PSScriptRoot/stop-request.json" $Nonce)
}
function Test-ExactClosure {
 if($pins.Count -ne 2 -or @($pins|Where-Object {$_.Alive}).Count){return $false}
 $script:exitVerified=$true
 $task=$service.GetFolder('\').GetTask('BimeronStep8Probe')
 Assert-ProbeRegistration $expected.registration (Get-ProbeRegistration $task)
 if($task.State -ne 3 -or $task.GetInstances(0).Count){return $false}
 $script:taskResult=[int]$task.LastTaskResult
 $script:taskClosureVerified=$true
 if($terminalDecision -eq 'completed' -and $task.LastTaskResult -ne 0){throw 'Natural completion task result nonzero'}
 return $true
}
try{
 if((Get-ProbeFileSHA256 $ExpectedPath) -ine $ExpectedSHA256){throw 'Independent expected artifact hash mismatch'}
 $expectedRaw=[IO.File]::ReadAllText($ExpectedPath);$expected=$expectedRaw|ConvertFrom-Json
 Assert-ExpectedSchema $expected $Nonce $PSScriptRoot
 foreach($item in @($expected.inputs)+@($expected.images.cmd,$expected.images.powershell)){
  $readPath=if($SmokeOnly -and $item.role -eq 'wrapper'){"$PSScriptRoot/planned-wrapper.ps1"}else{$item.path}
  if((Get-ProbeFileSHA256 $readPath) -ine $item.sha256){throw 'Expected input/image mismatch'}
 }
 if($LocalFixture){[Console]::WriteLine('Local fixture dependency/schema validation PASS; no Scheduler or Run');return}
 $inputs+=[IO.File]::Open($ExpectedPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 if((Get-ProbeFileSHA256 $ExpectedPath) -ine $ExpectedSHA256 -or [IO.File]::ReadAllText($ExpectedPath) -cne $expectedRaw){throw 'Expected artifact changed before pin'}
 $service=New-Object -ComObject Schedule.Service;$service.Connect();$registered=$service.GetFolder('\').GetTask('BimeronStep8Probe')
 Assert-ProbeRegistration $expected.registration (Get-ProbeRegistration $registered)
 if($registered.State -ne 3 -or $registered.GetInstances(0).Count -ne 0){throw 'Task not idle before launch'}
 if(!(Get-WinEvent -ListLog Microsoft-Windows-TaskScheduler/Operational).IsEnabled){throw 'Required Scheduler log unavailable'}
 foreach($item in @($expected.inputs)+@($expected.images.cmd,$expected.images.powershell)){
  $readPath=if($SmokeOnly -and $item.role -eq 'wrapper'){"$PSScriptRoot/planned-wrapper.ps1"}else{$item.path}
  $inputs+=[IO.File]::Open($readPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  if((Get-ProbeFileSHA256 $readPath) -ine $item.sha256){throw 'Expected input/image mismatch'}
 }
 $bookmark=(Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational -MaxEvents 1).RecordId
 if($SmokeOnly){[Console]::WriteLine('Prelaunch dependency/schema smoke PASS; no Run');return}
 $marker=[IO.File]::Open("$Root/provenance-launch.marker",[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);$marker.Dispose()
 $healthJournal=[ProbeJournal]::new("$Root/producer-health.jsonl")
 $before=[DateTime]::UtcNow.ToString('o')
 $request=Read-ProbeStop "$PSScriptRoot/stop-request.json" $Nonce
 if($request){$cancelled=$true;return}
 $launchNeverOccurred=$false
 $running=$registered.Run($null) # Exactly one call, no credentials or principal override.
 $guid=[Guid]::Parse($running.InstanceGuid).ToString()
 $launch=@{guid=$guid;engine=0;before=$before;bookmark=$bookmark;nonce=$Nonce}
 $launch|ConvertTo-Json|Set-Content "$Root/launch.json"
 while($timer.Elapsed.TotalSeconds -lt $Seconds){
  try{
   $request=Read-ProbeStop "$PSScriptRoot/stop-request.json" $Nonce
   if($request -and !$exitBudget){$exitBudget=[Diagnostics.Stopwatch]::StartNew()}
   if($exitBudget -and $exitBudget.Elapsed.TotalSeconds -ge 30){throw 'HOLD: cancellation exit deadline'}
   if($request -and !$ready){throw 'Cancellation before complete pin; closure evidence required'}
   if($ready){
    if(!$terminalDecision){
     $terminalBytes=[Text.UTF8Encoding]::new($false,$true).GetString([ProbeJournal]::Snapshot("$Root/probe-$Nonce.jsonl"))
     $lastLine=Get-ProbeLastCompleteRecord $terminalBytes
     if($lastLine.kind -eq 'end'){$terminalDecision=Read-BoundTerminal}
    }
    if($terminalDecision){
     if(!$exitBudget){$exitBudget=[Diagnostics.Stopwatch]::StartNew()};$terminalDrain=$exitBudget
     if(Test-ExactClosure){$cancelled=($terminalDecision -eq 'cancelled');$completed=(!$cancelled -and !$request);break}
     if($terminalDrain.Elapsed.TotalSeconds -ge 30){throw 'HOLD: terminal exit/task closure deadline'}
     Start-Sleep -Milliseconds 250;continue
    }
   }
   $running.Refresh();$engine=[int]$running.EnginePID
   if(!$launch.engine){if($engine -le 0){throw 'Waiting for returned instance engine'};$launch.engine=$engine;$pins+=[ProcessPin]::new($engine);$launch|ConvertTo-Json|Set-Content "$Root/launch.json"}
   $instance=@{guid=[Guid]::Parse($running.InstanceGuid).ToString();engine=$engine;path=$running.Path;state=[int]$running.State}
   if($ready){
    Assert-ProbeRegistration $expected.registration (Get-ProbeRegistration ($service.GetFolder('\').GetTask('BimeronStep8Probe')))
    if(Test-ProbeTerminalTransition $instance $launch $expected $pins){$terminalDecision=Read-BoundTerminal;continue}
   }
   if($pins.Count -lt 2){
    $children=@(Get-CimInstance Win32_Process -Filter "ParentProcessId=$engine"|Where-Object {$_.Name -eq 'powershell.exe'})
    if($children.Count -eq 0){throw 'Waiting for actual PowerShell child'}
    if($children.Count -ne 1){throw 'Ambiguous PowerShell child'}
    $pins+=[ProcessPin]::new([int]$children[0].ProcessId)
   }
   $liveChildren=@(Get-CimInstance Win32_Process -Filter "ParentProcessId=$engine"|Where-Object {$_.Name -eq 'powershell.exe'})
   if($liveChildren.Count -eq 0 -and !$pins[1].Alive){throw 'Process exited'}
   if($liveChildren.Count -ne 1 -or $liveChildren[0].ProcessId -ne $pins[1].Pid){throw 'Actual producer child changed/ambiguous'}
   $child=Get-CimInstance Win32_Process -Filter "ProcessId=$($pins[1].Pid)"
   if(!$child -and !$pins[1].Alive){throw 'Process exited'}
   if(!$child -or !(Test-ProbeCimCreation $child.CreationDate $pins[1].Start)){throw 'Actual producer identity missing/reused'}
   $parent=Facts $pins[0] 0;$producer=Facts $pins[1] ([int]$child.ParentProcessId)
   $records=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';Id=200} -MaxEvents 30|Where-Object {$_.RecordId -gt $bookmark}|ForEach-Object {
    [xml]$x=$_.ToXml();$fields=@{};foreach($d in $x.Event.EventData.Data){$fields[$d.Name]=$d.'#text'}
    if($fields.TaskInstanceId -and [Guid]::Parse($fields.TaskInstanceId).ToString() -eq $guid){@{guid=$guid;engine=[int]$fields.EnginePID;task=$fields.TaskName;action=$fields.ActionName;record=$_.RecordId;xml=$_.ToXml()}}
   })
   if($records.Count -eq 0){throw 'Waiting for instance event200'}
   if($records.Count -ne 1){throw 'Ambiguous instance event200'}
   $event=$records[0]
   $registered=$service.GetFolder('\').GetTask('BimeronStep8Probe')
   if(!$parent.alive -or !$producer.alive){
     # Validate every non-liveness field without changing either observation.
    Assert-ProbeNonLivenessProvenance $expected (Get-ProbeRegistration $registered) $launch $instance $event $parent $producer $pinned
    throw 'Process liveness mismatch'
   }
   Assert-ProbeProvenance $expected (Get-ProbeRegistration $registered) $launch $instance $event $parent $producer $pinned
   if([IO.File]::ReadAllText($ExpectedPath) -cne $expectedRaw){throw 'Expected artifact changed'}
   if(!(Test-Path "$Root/probe-$Nonce.jsonl")){throw 'Waiting for first producer record'}
   $bytes=[ProbeJournal]::Snapshot("$Root/probe-$Nonce.jsonl");$text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
   $first=Read-FirstProducerRecord $bytes $producer $Nonce $Root
   if(!$ready){
    $pinned=@{parent=$parent;producer=$producer}
    @{nonce=$Nonce;producer=$first.producer;process=@($producer,$parent);action=$expected.registration.action;inputs=$expected.inputs;launch=$launch;event200=$event;registration=$expected.registration}|ConvertTo-Json -Depth 10|Set-Content "$Root/producer-pin.json"
    $ready=$true
   }
   $complete=$text.LastIndexOf("`n")+1
   if($complete -gt $lastLength){$lastLength=$complete;$lastProgress=$timer.Elapsed.TotalSeconds}
   if($timer.Elapsed.TotalSeconds-$lastProgress -gt 8){throw 'Complete-record progress stalled'}
  }catch{
   $message=$_.Exception.Message
   $baseMessage=$_.Exception.GetBaseException().Message
   if($ready -and ((Test-ProbeExitRace $message $pins) -or (Test-ProbeExitRace $baseMessage $pins))){
    try{$terminalDecision=Read-BoundTerminal;continue}catch{if(!$failure){$failure=$_.Exception.Message}}
   }elseif($ready -or !$message.StartsWith('Waiting for ') -or $timer.Elapsed.TotalSeconds -gt 10){if(!$failure){$failure=$message}}
  }
  $healthJournal.Record((@{utc=[DateTime]::UtcNow.ToString('o');elapsed=$timer.Elapsed.TotalSeconds;ready=$ready;healthy=($ready -and !$failure);failure=$failure;completeBytes=$lastLength}|ConvertTo-Json -Compress))
  if($failure){break};Start-Sleep -Milliseconds 250
 }
 if($failure){throw $failure}
 if(!$ready){throw 'Authoritative producer provenance never ready'}
 if(!$completed -and !$cancelled){throw 'Finite producer completion not proven'}
}catch{if(!$failure){$failure=$_.Exception.Message}}finally{
 try {
  try {
  if(!$SmokeOnly -and ($failure -or (!$completed -and !$cancelled -and $launch))){
   $request=Read-ProbeStop "$PSScriptRoot/stop-request.json" $Nonce
   if(!$request){$request=[pscustomobject]@{schema=1;nonce=$Nonce;requestId=[Guid]::NewGuid().ToString('N');reasonCode='inspector-failure';requestedUtc=[DateTime]::UtcNow.ToString('o')};try{Publish-ProbeStop "$PSScriptRoot/stop-request.json" $request $Nonce}catch{if(!(Read-ProbeStop "$PSScriptRoot/stop-request.json" $Nonce)){throw}};$request=Read-ProbeStop "$PSScriptRoot/stop-request.json" $Nonce}
  }
  if(!$launchNeverOccurred -and !$taskClosureVerified){
   if(!$exitBudget){$exitBudget=[Diagnostics.Stopwatch]::StartNew()};$drain=$exitBudget
   while($drain.Elapsed.TotalSeconds -lt 30){
    if(Test-ExactClosure){break}
    if($pins.Count -ne 2){$holdReason='HOLD: launch attempted without both retained process pins';break}
    Start-Sleep -Milliseconds 250
   }
   if(!$exitVerified -and !$holdReason){$holdReason='HOLD: retained producer exit not verified within 30 seconds'}
   if($exitVerified -and !$taskClosureVerified){$holdReason='HOLD: task closure not verified within 30 seconds'}
  }
  if($launchNeverOccurred -and $registered){
   Assert-ProbeRegistration $expected.registration (Get-ProbeRegistration $registered)
   $taskClosureVerified=($registered.State -eq 3 -and $registered.GetInstances(0).Count -eq 0)
  }
  }catch{$holdReason='HOLD: closure verification failed: '+$_.Exception.Message}
  while(!$SmokeOnly -and !$launchNeverOccurred -and !$taskClosureVerified){
   if(!$holdReason){$holdReason='HOLD: unresolved retained producer/task drain'}
   [Console]::Error.WriteLine($holdReason)
   try{if(Test-ExactClosure){break}}catch{[Console]::Error.WriteLine($_.Exception.Message)}
   Start-Sleep -Milliseconds 250
  }
  if(!$SmokeOnly){
   Publish-ProbeJson "$Root/inspector-final.json" @{nonce=$Nonce;launch=$launch;launchNeverOccurred=$launchNeverOccurred;ready=$ready;completed=$completed;cancelled=$cancelled;requestId=$(if($request){$request.requestId}else{$null});failure=$failure;exitVerified=$exitVerified;taskClosureVerified=$taskClosureVerified;holdReason=$holdReason;taskResult=$taskResult;processes=@($pins|ForEach-Object {@{pid=$_.Pid;start=$_.Start;alive=$_.Alive}})}
  }
 }finally{
  $disposeErrors=@()
  foreach($p in @($pins)+@($inputs)+@($healthJournal|Where-Object {$_})){try{$p.Dispose()}catch{$disposeErrors+=$_.Exception.Message}}
  if($disposeErrors.Count){throw ($disposeErrors -join '; ')}
 }
}
if($failure -or $holdReason){throw "$failure $holdReason"}
