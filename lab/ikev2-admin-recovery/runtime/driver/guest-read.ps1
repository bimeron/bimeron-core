param([ValidateSet('clock','state','snapshot','ready','persistent','stop','drain-status','restore-permit','integration')][string]$Mode='clock',[string]$Nonce,[string]$ControlPath,[string]$Output,[ValidateRange(0,1000)][int]$TestReadHoldMs=0,[string]$TestReadyPath,[string]$TestDispatchPath,[string]$TestRole,$OwnedSession=$null,[string]$ClosurePath)
$ErrorActionPreference='Stop'
if($Mode -ne 'clock' -and $Nonce -notmatch '^[a-f0-9]{64}$'){throw 'Nonce'}
if($Mode -eq 'restore-permit'){
 . "$PSScriptRoot/cancellation.ps1"
 $permit=[IO.File]::ReadAllText("$(Resolve-ProbeControlRoot $PSScriptRoot $ControlPath $Nonce)/restore-permit.json")|ConvertFrom-Json
 Assert-ProbeRestorePermit $permit $Nonce
 $permit|ConvertTo-Json -Compress
 return
}
$code=[IO.File]::ReadAllText("$PSScriptRoot/Clock.cs")
$journal=[IO.File]::ReadAllText("$PSScriptRoot/Journal.cs")
if($null -ne $OwnedSession){
 if($Mode -cnotin @('clock','ready','integration')){throw 'Resident read mode forbidden'}
 $s=$OwnedSession
}else{
$cred=Import-Clixml (Join-Path $env:LOCALAPPDATA 'Bimeron/ikev2-clean-lab.credential.xml')
$mutex=[Threading.Mutex]::new($false,'Local\BimeronStep10-<LAB_VM_ID_PREFIX>-session-start');$locked=$false
try{
 $locked=$mutex.WaitOne(3000);if(!$locked){throw 'Session setup mutex timeout'}
 $s=New-PSSession -VMId '<LAB_VM_ID>' -Credential $cred
}finally{if($locked){$mutex.ReleaseMutex()};$mutex.Dispose()}
}
try{
 if($Mode -in @('stop','drain-status','restore-permit')){
  $request=$null
  if($Mode -eq 'stop'){
   . "$PSScriptRoot/cancellation.ps1"
   $request=Read-ProbeStop "$(Resolve-ProbeControlRoot $PSScriptRoot $ControlPath $Nonce)/stop-request.json" $Nonce
   if(!$request){throw 'Host stop request missing'}
  }
  Invoke-Command -Session $s -ArgumentList $Mode,$Nonce,$request,([IO.File]::ReadAllText("$PSScriptRoot/cancellation.ps1")) -ScriptBlock {
   param($mode,$nonce,$request,$helper)
   . ([ScriptBlock]::Create($helper))
   $root="C:/BimeronStep10Probe/$nonce"
   if($mode -eq 'stop'){
    if(!(Test-Path -LiteralPath $root)){return (@{nonce=$nonce;delivered=$false;reason='not-created'}|ConvertTo-Json -Compress)}
    $existing=Read-ProbeStop "$root/stop-request.json" $nonce
    if(!$existing){try{Publish-ProbeStop "$root/stop-request.json" $request $nonce}catch{if(!(Read-ProbeStop "$root/stop-request.json" $nonce)){throw}}}
    $request=Read-ProbeStop "$root/stop-request.json" $nonce
    return (@{nonce=$nonce;delivered=$true;requestId=$request.requestId;stopRequest=$request;adoptedRequest=$request}|ConvertTo-Json -Compress)
   }
   $readers=@{}
   foreach($role in @('supervisor','collector','barrier')){
    $records=@{ready=$null;closed=$null}
    foreach($kind in @('ready','closed')){
     $path="$root/logs/reader-$role-$kind.json"
     if(Test-Path -LiteralPath $path){$record=[IO.File]::ReadAllText($path)|ConvertFrom-Json;if($record.nonce -cne $nonce -or $record.role -cne $role){throw 'Reader evidence binding'};$records[$kind]=$record}
    }
    $readers[$role]=$records
   }
   $final=$null
   if(Test-Path "$root/logs/inspector-final.json"){$final=[IO.File]::ReadAllText("$root/logs/inspector-final.json")|ConvertFrom-Json}
   $service=New-Object -ComObject Schedule.Service;$service.Connect();$task=$service.GetFolder('\').GetTask('BimeronStep8Probe')
   @{nonce=$nonce;stopRequest=(Read-ProbeStop "$root/stop-request.json" $nonce);readers=$readers;inspectorFinal=$final;task=@{state=[int]$task.State;instances=[int]$task.GetInstances(0).Count}}|ConvertTo-Json -Depth 12 -Compress
  }
  return
 }
 if($Mode -eq 'persistent'){
  if($TestRole -cnotin @('supervisor','collector','barrier')){throw 'Invalid persistent reader role'}
  . "$PSScriptRoot/cancellation.ps1"
  Publish-ProbeJson "$(Resolve-ProbeControlRoot $PSScriptRoot $ControlPath $Nonce)/reader-$TestRole-session-open.json" @{schema=1;nonce=$Nonce;role=$TestRole;sessionOpenedUtc=[DateTime]::UtcNow.ToString('o')}
  $body=[ScriptBlock]::Create([IO.File]::ReadAllText("$PSScriptRoot/persistent-reader.ps1"))
  Invoke-Command -Session $s -ScriptBlock $body -ArgumentList $journal,([IO.File]::ReadAllText("$PSScriptRoot/reader-health.ps1")),$Nonce,$TestRole,([IO.File]::ReadAllText("$PSScriptRoot/cancellation.ps1"))
  return
 }
 if($TestReadyPath -or $TestDispatchPath){
  if(!$TestReadyPath -or !$TestDispatchPath -or $TestReadHoldMs -eq 0 -or $TestRole -notin @('supervisor','collector','barrier')){throw 'Incomplete test rendezvous'}
  if(($TestRole -eq 'supervisor') -ne ($Mode -eq 'state')){throw 'Test role/mode mismatch'}
  $pending=$TestReadyPath+'.pending';$ready=[IO.File]::Open($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$b=[Text.Encoding]::ASCII.GetBytes((@{nonce=$Nonce;role=$TestRole}|ConvertTo-Json -Compress));$ready.Write($b,0,$b.Length);$ready.Flush($true)}finally{$ready.Dispose()}
  [IO.File]::Move($pending,$TestReadyPath)
  $wait=[Diagnostics.Stopwatch]::StartNew()
  while(!(Test-Path -LiteralPath $TestDispatchPath) -and $wait.Elapsed.TotalSeconds -lt 10){Start-Sleep -Milliseconds 20}
  if(!(Test-Path -LiteralPath $TestDispatchPath)){throw 'Test dispatch timeout'}
  $dispatch=[IO.File]::ReadAllText($TestDispatchPath)|ConvertFrom-Json
  if($dispatch.nonce -ne $Nonce -or ($dispatch.roles -join ',') -ne 'supervisor,collector,barrier'){throw 'Test dispatch mismatch'}
 }
 # Use the host's trusted deployed source even if preparation stopped before
 # provenance.ps1 reached the guest. This collects registration, not proof of drain.
 $provenanceCode=if($Mode -eq 'integration'){[IO.File]::ReadAllText("$PSScriptRoot/provenance.ps1")}else{''}
 $value=Invoke-Command -Session $s -ArgumentList $code,$journal,$Mode,$Nonce,$TestReadHoldMs,([IO.File]::ReadAllText("$PSScriptRoot/reader-health.ps1")),$provenanceCode -ScriptBlock {
  param($clockCode,$journalCode,$mode,$nonce,$hold,$healthCode,$provenanceCode)
  . ([ScriptBlock]::Create($healthCode))
  Add-Type -TypeDefinition $clockCode;Add-Type -TypeDefinition $journalCode
  $clock=[LabClock]::Read()|ConvertFrom-Json
  if($mode -eq 'clock'){return ($clock|ConvertTo-Json -Compress)}
  $root="C:/BimeronStep10Probe/$nonce";$log="$root/logs/probe-$nonce.jsonl"
  if($mode -eq 'ready'){
   if(!(Test-Path "$root/logs/producer-pin.json") -or !(Test-Path $log) -or !(Test-Path "$root/logs/producer-health.jsonl")){return '{"ready":false,"healthy":false}'}
   $text=[Text.Encoding]::UTF8.GetString([ProbeJournal]::Snapshot("$root/logs/producer-health.jsonl"));$end=$text.LastIndexOf("`n")
   if($end -lt 0){return '{"ready":false,"healthy":false}'}
   $h=($text.Substring(0,$end).Trim().Split("`n")|Select-Object -Last 1)|ConvertFrom-Json
   Assert-HealthRecord $h
   if(!$h.ready){return ($h|ConvertTo-Json -Compress)}
   $pin=[IO.File]::ReadAllText("$root/logs/producer-pin.json")|ConvertFrom-Json
   Assert-ReaderHealth $h $pin $nonce
   return ($h|ConvertTo-Json -Compress)
  }
  $data=if($mode -eq 'integration' -and ![IO.File]::Exists($log)){,([byte[]]@())}else{,([ProbeJournal]::Snapshot($log,$hold))};$readBefore=[ProbeJournal]::LastReadOpenedUtc;$readAfter=[ProbeJournal]::LastReadClosedUtc
  if($mode -eq 'snapshot'){
   $destination="$root/closed-"+[Guid]::NewGuid().ToString('N')+'.jsonl'
   $f=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$f.Write($data,0,$data.Length);$f.Flush($true)}finally{$f.Dispose()}
   return (@{path=$destination;readBefore=$readBefore;readAfter=$readAfter;bytes=$data.Length}|ConvertTo-Json -Compress)
  }
  $pin=if([IO.File]::Exists("$root/logs/producer-pin.json")){[IO.File]::ReadAllText("$root/logs/producer-pin.json")|ConvertFrom-Json}else{$null}
  $healthBytes=if($mode -eq 'integration' -and ![IO.File]::Exists("$root/logs/producer-health.jsonl")){,([byte[]]@())}else{,([ProbeJournal]::Snapshot("$root/logs/producer-health.jsonl"))}
  $healthText=[Text.Encoding]::UTF8.GetString($healthBytes);$end=$healthText.LastIndexOf("`n")
  if($end -lt 0 -and $mode -ne 'integration'){throw 'Incomplete producer health'}
  $health=if($end -lt 0){$null}else{($healthText.Substring(0,$end).Trim().Split("`n")|Select-Object -Last 1)|ConvertFrom-Json}
  if($end -ge 0 -and $null -eq $health){throw 'Invalid complete producer health record'}
  if($mode -eq 'integration'){
   $files=@{}
   foreach($entry in @(@('original-producer-pin.json','logs/producer-pin.json'),@('expected.json','expected.json'),@('launch.json','logs/launch.json'),@('inspector-exit-proof.json','inspector-exit-proof.json'),@('inspector-final.json','logs/inspector-final.json'),@('stop-request.json','stop-request.json'))){
    $path="$root/$($entry[1])";if([IO.File]::Exists($path)){$files[$entry[0]]=[Convert]::ToBase64String([IO.File]::ReadAllBytes($path))}
   }
   foreach($role in @('supervisor','collector','barrier')){foreach($kind in @('ready','closed')){$path="$root/logs/reader-$role-$kind.json";if([IO.File]::Exists($path)){$files["reader-$role-$kind.json"]=[Convert]::ToBase64String([IO.File]::ReadAllBytes($path))}}}
   . ([ScriptBlock]::Create($provenanceCode))
   $svc=New-Object -ComObject Schedule.Service;$svc.Connect();$task=$svc.GetFolder('\').GetTask('BimeronStep8Probe')
   $reg=Get-ProbeRegistration $task
   $files['registration.json']=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($reg|ConvertTo-Json -Depth 12 -Compress)))
   $launch=if([IO.File]::Exists("$root/logs/launch.json")){[IO.File]::ReadAllText("$root/logs/launch.json")|ConvertFrom-Json}else{$null}
   $readback=@{schema='full300-task-readback-v1';nonce=$nonce;path='\BimeronStep8Probe';registration=$null;launchInstanceGuid=$launch.guid;state=[int]$task.State;instanceGuids=@($task.GetInstances(0)|ForEach-Object {[string]$_.InstanceGuid});lastTaskResult=[int]$task.LastTaskResult}
   $bfe=Join-Path $env:TEMP ('full300-'+[guid]::NewGuid().ToString('N')+'.xml');& 'C:/Windows/System32/netsh.exe' wfp show state "file=$bfe"|Out-Null;if($LASTEXITCODE){throw 'BFE read failed'}
   return (@{exactPorts=@(Get-NetUDPEndpoint -ErrorAction Stop|Where-Object {$_.LocalPort -in @(500,4500)}|ForEach-Object {@{address=$_.LocalAddress;port=[int]$_.LocalPort;pid=[int]$_.OwningProcess}});nonce=$nonce;probe=[Convert]::ToBase64String($data);files=$files;readiness=$health;task=$readback;bfe=[Convert]::ToBase64String([IO.File]::ReadAllBytes($bfe));ras=[string](& 'C:/Windows/System32/rasdial.exe'|Out-String);clock=([LabClock]::Read()|ConvertFrom-Json)}|ConvertTo-Json -Depth 16 -Compress)
  }
  $owners=@(Get-CimInstance Win32_Process -Filter "Name='step10-candidate.exe'"|ForEach-Object {@{pid=$_.ProcessId;start=$_.CreationDate.ToUniversalTime().ToString('o');path=$_.ExecutablePath}})
  $bfe=Join-Path $env:TEMP ('step10-observe-'+[Guid]::NewGuid().ToString('N')+'.xml')
  & 'C:/Windows/System32/netsh.exe' wfp show state "file=$bfe"|Out-Null;if($LASTEXITCODE){throw 'BFE read failed'}
  @{clock=$clock;owners=$owners;readBefore=$readBefore;readAfter=$readAfter;probeLength=$data.Length;probe=[Convert]::ToBase64String($data);pin=$pin;producerHealth=$health;ras=[string](& 'C:/Windows/System32/rasdial.exe'|Out-String);bfePath=$bfe;bfe=[IO.File]::ReadAllText($bfe)}|ConvertTo-Json -Depth 8 -Compress
 }
 if($Mode -eq 'snapshot'){
  if(!$Output -or (Test-Path -LiteralPath $Output)){throw 'Fresh snapshot output required'}
  $descriptor=$value|ConvertFrom-Json
  Copy-Item -FromSession $s -LiteralPath $descriptor.path -Destination $Output -ErrorAction Stop
  $value
 }else{$value}
}finally{
 if($null -eq $OwnedSession){
  if($ClosurePath){
   . "$PSScriptRoot/cancellation.ps1"
   Publish-ProbeJson ($ClosurePath+'.reserved') @{nonce=$Nonce;pid=$PID;instanceId=$s.InstanceId.ToString()}
   try{Remove-PSSession -Session $s -ErrorAction Stop}catch{$closureError=$_}
   # Original session stays reachable after uncertain close. No repeated Remove.
   while([string]$s.State -cne 'Closed'){Start-Sleep -Milliseconds 250}
   Publish-ProbeJson $ClosurePath @{nonce=$Nonce;pid=$PID;creationFileTime=[string](Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc();instanceId=$s.InstanceId.ToString();state=[string]$s.State}
  }else{Remove-PSSession $s}
 }
}
