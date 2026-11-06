param(
 [ValidateSet('preflight','launch','sample','start','cleanup','final','principal','challenge','transition')][string]$Operation,
 [ValidatePattern('^[a-f0-9]{64}$')][string]$Nonce,
 [string]$RequestPath,
 [ValidateSet('submit','fetch')][string]$Mode='submit'
)
# Adapter.rpc(operation, frozenPath): map submit/fetch to -Mode; pass the envelope
# as -RequestPath and map its op to Operation (seal/exit use final). stdout is raw
# response JSON. Preflight RequestPath is config.json; sibling deployment.json is
# a frozen {files:[{name,sha256,length}]} ledger, with source bytes in deployment/.
# Host archives response refs beside config in samples/ and proofs/. A timeout
# requires Mode fetch: never repeat preflight, Run, or an uncertain submission.
$ErrorActionPreference='Stop'
. "$PSScriptRoot/owner-mailbox.ps1"
# These helpers accept scheduler objects so offline tests never activate COM.
function Get-OwnerTaskRegistration($Task) {
 @{xml=[string]$Task.Xml;sddl=[string]$Task.GetSecurityDescriptor(7)}
}
function Assert-OwnerTaskBaseline($Task,$Baseline) {
 $actual=Get-OwnerTaskRegistration $Task
 if($actual.xml -cne $Baseline.xml -or $actual.sddl -cne $Baseline.sddl){throw 'HOLD: task registration changed'}
 if(!$Baseline.fileSddl -or (Get-OwnerTaskFileSddl $Task.Name) -cne $Baseline.fileSddl){throw 'HOLD: task file ACL changed or baseline missing'}
}
function Wait-OwnerTaskExit($Task,$Baseline,[string]$InstanceGuid,[int]$Attempts=30,[scriptblock]$Pause={Start-Sleep -Seconds 1}) {
 if(!$InstanceGuid -or $Attempts -lt 1 -or $Attempts -gt 60){throw 'HOLD: missing owned instance or invalid observation bound'}
 $parsed=[guid]::Empty
 if(![guid]::TryParse($InstanceGuid,[ref]$parsed) -or $parsed -eq [guid]::Empty){throw 'HOLD: invalid owned instance'}
 for($i=0;$i -lt $Attempts;$i++) {
  Assert-OwnerTaskBaseline $Task $Baseline
  $instances=@($Task.GetInstances(0)|ForEach-Object {[string]$_.InstanceGuid})
  if($instances.Count -eq 0 -and $Task.State -eq 3){
   return @{xml=[string]$Task.Xml;sddl=[string]$Task.GetSecurityDescriptor(7);fileSddl=$Baseline.fileSddl;instanceGuid=$InstanceGuid;instanceGuids=$instances;state=3;lastTaskResult=$Task.LastTaskResult}
  }
  if(@($instances|Where-Object {$_ -ine $InstanceGuid}).Count){throw 'HOLD: unexpected task instance'}
  if($i+1 -lt $Attempts){& $Pause}
 }
 throw 'HOLD: owned task has not ended within observation bound'
}
function Open-OwnerSession($Retention=$null) {
 $cred=Import-Clixml (Join-Path $env:LOCALAPPDATA 'Bimeron/ikev2-clean-lab.credential.xml')
 # Share the producer readers' bounded startup lock; release before remote work.
 $mutex=[Threading.Mutex]::new($false,'Local\BimeronStep10-<LAB_VM_ID_PREFIX>-session-start');$locked=$false
 try {
  $locked=$mutex.WaitOne(3000);if(!$locked){throw 'Session setup mutex timeout'}
  if($null -ne $Retention){
   if($Retention.sessionAttempted){throw 'Original session already attempted'}
   $Retention.sessionAttempted=$true
  }
  $s=New-PSSession -VMId '<LAB_VM_ID>' -Credential $cred
  if($null -ne $Retention){$Retention.session=$s}
 } finally {if($locked){$mutex.ReleaseMutex()};$mutex.Dispose()}
 try {
  $name=Invoke-Command -Session $s -ArgumentList $Nonce,($null -ne $Retention) -ScriptBlock {
   param($nonce,$retained)
   $ErrorActionPreference='Stop'
   if($env:COMPUTERNAME -cne '<LAB_GUEST_NAME>'){throw 'Guest identity mismatch'}
   if((Get-ExecutionPolicy -Scope MachinePolicy) -ne 'Undefined' -or (Get-ExecutionPolicy -Scope UserPolicy) -ne 'Undefined'){throw 'Managed execution policy present'}
   $before=@{};foreach($scope in @('MachinePolicy','UserPolicy','CurrentUser','LocalMachine')){$before[$scope]=[string](Get-ExecutionPolicy -Scope $scope)}
   if($retained){
    if(Get-Variable BimeronOriginalProcessPolicy -Scope Global -ErrorAction SilentlyContinue){throw 'Original policy already captured'}
    $global:BimeronOriginalProcessPolicy=@{nonce=$nonce;value=[string](Get-ExecutionPolicy -Scope Process);restored=$false}
   }
   # Only this disposable PSDirect process; no user or machine policy change.
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
   if((Get-ExecutionPolicy) -ne 'Bypass'){throw 'Session execution policy refused'}
   foreach($scope in $before.Keys){if([string](Get-ExecutionPolicy -Scope $scope) -cne $before[$scope]){throw 'Persistent execution policy changed'}}
   $env:COMPUTERNAME
  }
  if($name -cne '<LAB_GUEST_NAME>'){throw 'Guest identity mismatch'}
 } catch {if($null -eq $Retention){Remove-PSSession $s};throw}
 return $s
}
function Install-OwnerTask($Session,$Root,$ConfigPath) {
 $configBytes=[IO.File]::ReadAllBytes($ConfigPath);$config=Assert-StrictOwnerJson $configBytes
 $base=Split-Path $ConfigPath
 $ledgerBytes=[IO.File]::ReadAllBytes((Join-Path $base 'deployment.json'))
 $ledger=Assert-StrictOwnerJson $ledgerBytes
 if($config.nonce -cne $Nonce -or $config.vm -cne '<LAB_VM_ID>' -or $config.guest -cne '<LAB_GUEST_NAME>' -or $config.principalName -cne '<LAB_GUEST_NAME>\test' -or $config.taskName -cne "BimeronFull300Owner-$Nonce" -or (Get-OwnerSHA256 $ledgerBytes) -cne $config.ledgerSHA256){throw 'Configuration mismatch'}
 $files=@();foreach($f in $ledger.files){
  if($f.name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$' -or $f.name.Contains('..')){throw 'Deployment basename'}
  $b=[IO.File]::ReadAllBytes((Join-Path "$base/deployment" $f.name))
  if($b.Length -ne $f.length -or (Get-OwnerSHA256 $b) -cne $f.sha256){throw 'Deployment digest'}
  $files+=@{name=$f.name;bytes=$b}
 }
 foreach($pair in @(@('owner-supervisor.ps1',$config.supervisorSHA256),@('full300-owner.exe',$config.ownerSHA256))){$file=@($files|Where-Object name -CEQ $pair[0]);if($file.Count -ne 1 -or (Get-OwnerSHA256 $file[0].bytes) -cne $pair[1]){throw 'Missing bound source'}}
 $result=Invoke-Command -Session $Session -ArgumentList $Root,$config,$configBytes,$ledgerBytes,$files -ScriptBlock {
  param($root,$c,$cb,$lb,$files)
  $sid=([Security.Principal.NTAccount]'<LAB_GUEST_NAME>\test').Translate([Security.Principal.SecurityIdentifier]).Value
  if($c.principalSid -cne $sid){throw 'Principal SID mismatch'}
  $svc=New-Object -ComObject Schedule.Service;$svc.Connect();$folder=$svc.GetFolder('\')
  $old=$folder.GetTask('BimeronStep9ABIActual');$p=$old.Definition.Principal
  $oldSid=try{([Security.Principal.NTAccount]$p.UserId).Translate([Security.Principal.SecurityIdentifier]).Value}catch{$p.UserId}
  if($oldSid -cne $sid -or $p.LogonType -ne 3 -or $p.RunLevel -ne 1){throw 'Historical principal verification failed'}
  if(@($folder.GetTasks(1)|Where-Object Name -EQ $c.taskName).Count -or (Test-Path -LiteralPath $root)){throw 'Exclusive root/task collision'}
  $parent=Split-Path $root
  if(!(Test-Path $parent)){New-Item -ItemType Directory -Path $parent|Out-Null}
  for($a=Get-Item $parent;$null -ne $a;$a=$a.Parent){if($a.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse ancestor'}}
  New-Item -ItemType Directory -Path $root -ErrorAction Stop|Out-Null
  $acl=New-Object Security.AccessControl.DirectorySecurity
  $acl.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$sid)")
  Set-Acl -LiteralPath $root -AclObject $acl
  foreach($dir in @('transport','transport/commands','transport/responses','transport/proofs','transport/samples')){New-Item -ItemType Directory -Path "$root/$dir"|Out-Null}
  foreach($f in $files){[IO.File]::WriteAllBytes("$root/$($f.name)",[byte[]]$f.bytes)}
  . "$root/owner-mailbox.ps1"
  . "$root/task-readback.ps1"
  [IO.File]::WriteAllBytes("$root/transport/config.json",$cb);[IO.File]::WriteAllBytes("$root/deployment.json",$lb)
  $d=$svc.NewTask(0);$d.Principal.UserId=$sid;$d.Principal.LogonType=3;$d.Principal.RunLevel=1
  $d.Settings.RestartCount=0;$d.Settings.MultipleInstances=2;$d.Settings.ExecutionTimeLimit='PT0S';$d.Settings.AllowHardTerminate=$false
  $d.Settings.StopIfGoingOnBatteries=$false;$d.Settings.DisallowStartIfOnBatteries=$false;$d.Settings.RunOnlyIfIdle=$false;$d.Settings.IdleSettings.StopOnIdleEnd=$false
  $action=$d.Actions.Create(0);$action.Path="$env:SystemRoot/System32/WindowsPowerShell/v1.0/powershell.exe"
  $action.Arguments="-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$root/owner-supervisor.ps1`" -Nonce $($c.nonce)"
  $task=$folder.RegisterTaskDefinition($c.taskName,$d,2,$sid,$null,3,"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$sid)")
  $registration=Assert-OwnerTaskReadback -Task $task -Definition $d -TaskName $c.taskName -PrincipalSID $sid
  [IO.File]::WriteAllBytes("$root/transport/task-registration.json",[Text.Encoding]::UTF8.GetBytes(($registration|ConvertTo-Json -Compress)))
  $registration
 }
 # Exactly one registration record; anything else is unresolved before Run.
 if(@($result).Count -ne 1 -or $result -isnot [Collections.IDictionary] -or @('xml','sddl','fileSddl'|Where-Object {!$result.Contains($_) -or $result[$_] -isnot [string]}).Count){throw 'HOLD: task registration readback missing'}
 Publish-OwnerBytesOnce (Join-Path $base 'task-registration.json') ([Text.Encoding]::UTF8.GetBytes(($result|ConvertTo-Json -Compress))) -Root $base
 $intent=Join-Path $base 'task-start-intent.json'
 if(Test-Path $intent){throw 'Run already attempted; reconcile only'}
 Publish-OwnerBytesOnce $intent ([Text.Encoding]::UTF8.GetBytes(($config|ConvertTo-Json -Compress))) -Root $base
 $guid=Invoke-Command -Session $Session -ArgumentList $config.taskName,$result,$Root -ScriptBlock {param($name,$baseline,$root). "$root/owner-mailbox.ps1";$svc=New-Object -ComObject Schedule.Service;$svc.Connect();$task=$svc.GetFolder('\').GetTask($name);if($task.Xml -cne $baseline.xml -or $task.GetSecurityDescriptor(7) -cne $baseline.sddl -or (Get-OwnerTaskFileSddl $name) -cne $baseline.fileSddl){throw 'Task changed before Run'};$instance=$task.Run($null);$instance.InstanceGuid}
 Publish-OwnerBytesOnce (Join-Path $base 'task-instance.json') ([Text.Encoding]::UTF8.GetBytes((@{instanceGuid=[string]$guid}|ConvertTo-Json -Compress))) -Root $base
 $guid
}
function Fetch-OwnerReady($Session,$Root,$Path){
 $base=Split-Path $Path
 $bytes=Invoke-Command -Session $Session -ArgumentList $Root -ScriptBlock {param($root)
  . "$root/owner-mailbox.ps1";$watch=[Diagnostics.Stopwatch]::StartNew()
  while($true){try{return ,(Read-OwnerBytes "$root/transport/proofs/supervisor-once.json" -Root $root)}catch{$e=$_.Exception;while($e.InnerException){$e=$e.InnerException};if($e -isnot [IO.FileNotFoundException] -or $watch.Elapsed.TotalSeconds -ge 20){throw};Start-Sleep -Milliseconds 100}}
 }
 Publish-OwnerBytesOnce "$base/proofs/supervisor-once.json" $bytes -Root $base
 [Text.Encoding]::UTF8.GetString($bytes)
}
function Submit-OwnerCommand($Session,$Root,$Path) {
 $base=Split-Path (Split-Path $Path);$raw=[IO.File]::ReadAllBytes($Path)
 $c=Assert-StrictOwnerJson $raw;$cfg=[IO.File]::ReadAllBytes("$base/config.json")
 $c=Assert-OwnerEnvelope $raw $Nonce (Get-OwnerSHA256 $cfg) $c.seq
 $refs=@(Get-OwnerTransitiveProofs $c.body $base $base)
 Invoke-Command -Session $Session -ArgumentList $Root,$raw,$refs,$c.seq -ScriptBlock {param($root,$raw,$refs,$seq). "$root/owner-mailbox.ps1";foreach($r in $refs){$dir=Get-OwnerReferenceNamespace $r.name;Publish-OwnerBytesOnce "$root/transport/$dir/$($r.name)" $r.bytes -Root $root -MaxBytes 67108864};Publish-OwnerBytesOnce ("$root/transport/commands/{0:D8}.json" -f [long]$seq) $raw -Root $root}

 Fetch-OwnerResponse $Session $Root $Path
}
function Fetch-OwnerResponse($Session,$Root,$Path) {
 $base=Split-Path (Split-Path $Path);$raw=[IO.File]::ReadAllBytes($Path);$c=Assert-StrictOwnerJson $raw
 $bundle=Invoke-Command -Session $Session -ArgumentList $Root,$c.seq -ScriptBlock {
  param($root,$seq). "$root/owner-mailbox.ps1"
  $deadline=[Diagnostics.Stopwatch]::StartNew()
  while($true){try{$bytes=Read-OwnerBytes ("$root/transport/responses/{0:D8}.json" -f [long]$seq) -Root $root;break}catch{$e=$_.Exception;while($e.InnerException){$e=$e.InnerException};if($e -isnot [IO.FileNotFoundException] -or $deadline.Elapsed.TotalSeconds -ge 20){throw};Start-Sleep -Milliseconds 100}}
  $r=Assert-StrictOwnerJson $bytes;$files=@()
  foreach($ref in $r.refs){Assert-OwnerRefs $ref;$dir=Get-OwnerReferenceNamespace $ref.name;$files+=@{dir=$dir;ref=$ref;bytes=(Read-OwnerBytes "$root/transport/$dir/$($ref.name)" -Root $root -MaxBytes 67108864)}}
  @{bytes=$bytes;files=$files}
 }
 # Exactly one {bytes,files} bundle; absent output or members is unresolved.
 if(@($bundle).Count -ne 1 -or $bundle -isnot [Collections.IDictionary] -or !$bundle.Contains('bytes') -or !$bundle.Contains('files') -or $bundle['bytes'] -isnot [byte[]]){throw 'HOLD: Response bundle missing'}
 $r=Assert-StrictOwnerJson $bundle.bytes
 if($r.nonce -cne $Nonce -or $r.configSHA256 -cne $c.configSHA256 -or $r.seq -ne $c.seq -or $r.commandSHA256 -cne (Get-OwnerSHA256 $raw)){throw 'Response binding mismatch'}
 foreach($f in @($bundle.files)){if($f -isnot [Collections.IDictionary] -or !$f.Contains('dir') -or !$f.Contains('ref') -or $f['bytes'] -isnot [byte[]]){throw 'HOLD: Response reference bundle'};Assert-OwnerRefs $f.ref;if($f.dir -cne (Get-OwnerReferenceNamespace $f.ref.name)){throw 'HOLD: Response reference namespace'};if($f.bytes.Length -ne $f.ref.length -or (Get-OwnerSHA256 $f.bytes) -cne $f.ref.sha256){throw 'Response reference mismatch'};Publish-OwnerBytesOnce "$base/$($f.dir)/$($f.ref.name)" $f.bytes -Root $base -MaxBytes 67108864}
 Publish-OwnerBytesOnce "$base/responses/$([IO.Path]::GetFileName($Path))" $bundle.bytes -Root $base
 [Text.Encoding]::UTF8.GetString($bundle.bytes)
}
function Reconcile-OwnerLaunch($Session,$Root,$Path){Fetch-OwnerResponse $Session $Root $Path}
function Complete-OwnerFinal($Session,$Root,$Path) {
 $base=Split-Path (Split-Path $Path)
 $raw=Read-OwnerBytes $Path 1048576 $base
 $cfg=Read-OwnerBytes "$base/config.json" 1048576 $base
 $config=Assert-StrictOwnerJson $cfg
 $command=Assert-StrictOwnerJson $raw
 $command=Assert-OwnerEnvelope $raw $Nonce (Get-OwnerSHA256 $cfg) $command.seq
 if($command.op -cne 'exit-supervisor'){return}
 $name="BimeronFull300Owner-$Nonce"
 if($config.nonce -cne $Nonce -or $config.taskName -cne $name){throw 'HOLD: configuration mismatch'}
 # Strict-mode safe: the body holds exactly one of ownerExit/noLaunch.
 $ownerExit=@($command.body.PSObject.Properties|Where-Object {$_.Name -ceq 'ownerExit'}).Count -eq 1
 $ref=if($ownerExit){$command.body.ownerExit}else{$command.body.noLaunch}
 $proof=Read-OwnerBytes "$base/proofs/$($ref.name)" 1048576 $base
 if($proof.Length -ne $ref.length -or (Get-OwnerSHA256 $proof) -cne $ref.sha256){throw 'HOLD: proof mismatch'}
 $p=Assert-StrictOwnerJson $proof
 $readyBytes=Invoke-Command -Session $Session -ArgumentList $Root -ScriptBlock {param($root). "$root/owner-mailbox.ps1";Read-OwnerBytes "$root/transport/proofs/supervisor-exit-ready.json" 1048576 $root}
 $ready=Assert-StrictOwnerJson $readyBytes
 Assert-OwnerFields $ready @('schema','nonce','configSHA256','supervisorOnceSHA256','exitCommandSHA256','proofSHA256','reason')
 $reason=if($ownerExit){'owner-signalled'}else{'sealed-no-launch'}
 if($ready.schema -cne 'full300-supervisor-exit-v1' -or $ready.nonce -cne $Nonce -or $ready.configSHA256 -cne (Get-OwnerSHA256 $cfg) -or $ready.exitCommandSHA256 -cne (Get-OwnerSHA256 $raw) -or $ready.proofSHA256 -cne $ref.sha256 -or $ready.reason -cne $reason -or $ready.supervisorOnceSHA256 -cnotmatch '^[a-f0-9]{64}$' -or $ready.supervisorOnceSHA256 -cne $p.supervisorOnceSHA256 -or $p.nonce -cne $Nonce -or $p.configSHA256 -cne $ready.configSHA256){throw 'HOLD: exit-ready binding mismatch'}
 $baseline=Assert-StrictOwnerJson (Read-OwnerBytes "$base/task-registration.json" 1048576 $base)
 $instance=Assert-StrictOwnerJson (Read-OwnerBytes "$base/task-instance.json" 1048576 $base)
 $helpers=@(${function:Get-OwnerTaskRegistration}.ToString(),${function:Assert-OwnerTaskBaseline}.ToString(),${function:Wait-OwnerTaskExit}.ToString(),${function:Get-OwnerTaskFileSddl}.ToString())
 $observe={param($name,$baseline,$id,$helpers,$delete)
  Set-Item function:Get-OwnerTaskRegistration ([scriptblock]::Create($helpers[0]))
  Set-Item function:Assert-OwnerTaskBaseline ([scriptblock]::Create($helpers[1]))
  Set-Item function:Wait-OwnerTaskExit ([scriptblock]::Create($helpers[2]))
  Set-Item function:Get-OwnerTaskFileSddl ([scriptblock]::Create($helpers[3]))
  $svc=New-Object -ComObject Schedule.Service;$svc.Connect();$folder=$svc.GetFolder('\');$task=$folder.GetTask($name)
  $result=Wait-OwnerTaskExit $task $baseline $id
  if($delete){$folder.DeleteTask($name,0)}else{$result}
 }
 $observation=Invoke-Command -Session $Session -ScriptBlock $observe -ArgumentList $name,$baseline,$instance.instanceGuid,$helpers,$false
 Publish-OwnerBytesOnce "$base/proofs/supervisor-exit-ready.json" $readyBytes $base
 Publish-OwnerBytesOnce "$base/task-final.json" ([Text.Encoding]::UTF8.GetBytes(($observation|ConvertTo-Json -Depth 10 -Compress))) $base
 # Recheck registration and instances after durable archival, immediately before deletion.
 Invoke-Command -Session $Session -ScriptBlock $observe -ArgumentList $name,$baseline,$instance.instanceGuid,$helpers,$true
}
function Publish-ProducerChallenge($Session,$OwnerRoot,$Path,$Kind) {
 $raw=[IO.File]::ReadAllBytes($Path);$c=Assert-StrictOwnerJson $raw
 $name=if($Kind -ceq 'challenge'){'post-arm.json'}else{'transition.json'}
 if($raw.Length -gt 16384 -or $c.nonce -cne $Nonce){throw 'Challenge bounds/binding'}
 $receipt=Invoke-Command -Session $Session -ArgumentList $OwnerRoot,$Nonce,$raw,$name,$Kind -ScriptBlock {
  param($ownerRoot,$nonce,$raw,$name,$kind)
  $ErrorActionPreference='Stop';. "$ownerRoot/owner-mailbox.ps1"
  $root="C:/BimeronStep10Probe/$nonce"
  $c=Assert-StrictOwnerJson $raw
  if($kind -ceq 'challenge'){
   Assert-OwnerFields $c @('schema','nonce','measurementNonce','requestId','producerPinSHA256','policySHA256','ackSHA256','owner','producer')
   if($c.schema -cne 'c1pe-challenge-v1' -or $c.measurementNonce -cnotmatch '^[a-f0-9]{64}$' -or $c.measurementNonce -ceq $nonce -or $c.requestId -cnotmatch '^[a-f0-9]{32}$'){throw 'Challenge schema'}
   $pin=Read-OwnerBytes "$root/logs/producer-pin.json" -Root $root
   if((Get-OwnerSHA256 $pin) -cne $c.producerPinSHA256){throw 'Challenge producer pin mismatch'}
   $p=Assert-StrictOwnerJson $pin
   foreach($key in @('pid','start','sid')){if($p.producer.$key -cne $c.producer.$key){throw 'Challenge producer identity'}}
  }else{Assert-OwnerFields $c @('schema','nonce');if($c.schema -cne 'c1pe-transition-v1'){throw 'Transition schema'}}
  if($c.nonce -cne $nonce -or (Test-Path -LiteralPath "$root/$name")){throw 'Challenge duplicate/run mismatch'}
  Publish-OwnerBytesOnce "$root/$name" $raw -Root $root
  @{nonce=$nonce;sha256=(Get-OwnerSHA256 (Read-OwnerBytes "$root/$name" -Root $root));name=$name}|ConvertTo-Json -Compress
 }
 $receipt
}
if($MyInvocation.InvocationName -ne '.') {
 [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
 if(!$Operation -or !$Nonce -or (!$RequestPath -and $Operation -ne 'principal')){throw 'Operation, Nonce and RequestPath required'}
 # Check before opening a session. Fetch must never enter task deletion or
 # deployment. The original request, not the public final label, decides.
 if($Mode -ceq 'fetch') {
  $fetchCommand=Assert-StrictOwnerJson ([IO.File]::ReadAllBytes($RequestPath))
  if($Operation -ceq 'preflight' -or $fetchCommand.op -cnotin @('launch','sample','start','cleanup','seal-no-launch')){throw 'Unsafe fetch operation; retain original authority'}
 }
 $root="C:/BimeronFull300/$Nonce";$session=Open-OwnerSession
 try {
  if($Operation -eq 'principal'){Invoke-Command -Session $session -ScriptBlock {([Security.Principal.NTAccount]'<LAB_GUEST_NAME>\test').Translate([Security.Principal.SecurityIdentifier]).Value}}
  elseif($Operation -in @('challenge','transition')){if($Mode -cne 'submit'){throw 'No challenge retry'};Publish-ProducerChallenge $session $root $RequestPath $Operation}
  elseif($Operation -eq 'preflight'){$null=Install-OwnerTask $session $root $RequestPath;Fetch-OwnerReady $session $root $RequestPath}
  elseif($Mode -eq 'fetch'){Reconcile-OwnerLaunch $session $root $RequestPath}
  else {
   $cmd=Assert-StrictOwnerJson ([IO.File]::ReadAllBytes($RequestPath))
   $allowed=if($Operation -eq 'final'){@('sample','seal-no-launch','exit-supervisor')}else{@($Operation)}
   if($allowed -cnotcontains $cmd.op){throw 'Operation/envelope mismatch'}
   Submit-OwnerCommand $session $root $RequestPath
   if($Operation -eq 'final'){Complete-OwnerFinal $session $root $RequestPath}
  }
 } finally {Remove-PSSession $session}
}
