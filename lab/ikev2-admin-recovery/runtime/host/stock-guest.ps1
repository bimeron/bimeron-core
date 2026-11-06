# Journal is owned by the original PSSession, never reconstructed from disk.
$global:StockGuestPhases=@{}
function Invoke-StockGuestStep([string]$StepName,[scriptblock]$Action,[scriptblock]$Verify) {
 $ErrorActionPreference='Stop'
 if(!$global:StockGuestPhases.ContainsKey($StepName)) {
  $global:StockGuestPhases[$StepName]=@{name=$StepName;submission='Intent';actionResult=$null;result=$null;error=$null;verification='Pending';acknowledged=$false}
  $record=$global:StockGuestPhases[$StepName]
  try {$record.actionResult=& $Action;$record.submission='Returned'}
  catch {$record.submission='Unknown';$record.error=$_;throw}
 }
 $record=$global:StockGuestPhases[$StepName]
 if($record.submission -cne 'Returned'){throw ('HOLD: original guest mutation ownership unknown: '+$StepName)}
 if($record.verification -ceq 'Verified'){return $record.result}
 try {$record.result=& $Verify $record.actionResult;$record.verification='Verified'}
 catch {$record.error=$_;throw}
 return $record.result
}
function Get-StockGuestPhaseJournal {
 return @($global:StockGuestPhases.Values | ForEach-Object {@{name=$_.name;submission=$_.submission;verification=$_.verification;error=$(if($_.error){[string]$_.error.Exception.Message}else{$null})}})
}
# Loaded once into the retained PS Direct session. Functions make real operations
# only when called by the reviewed controller; development tests use mocks.
function Write-StockOnce([string]$Path,[byte[]]$Bytes) {
 $s=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$s.Write($Bytes,0,$Bytes.Length);$s.Flush($true)}finally{$s.Dispose()}
}
function Get-StockHash([byte[]]$Bytes) {
 $h=[Security.Cryptography.SHA256]::Create()
 try{return ([BitConverter]::ToString($h.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
}
function Assert-StockAncestors([string]$Path) {
 $p=Get-Item -LiteralPath $Path -ErrorAction Stop
 while($null -ne $p){
  if($p.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'HOLD: reparse ancestry'}
  if($p -is [IO.FileInfo]){$p=$p.Directory}else{$p=$p.Parent}
 }
}
function Get-StockContext {
 $pins=@()
 try {
  foreach($p in @(Get-Process explorer -ErrorAction Stop)){
   $pin=[StockProcessPin]::new($p.Id)
   if($pin.Sid -ceq '<LAB_GUEST_SID_1001>' -and $pin.Session -eq 2){$pins+=,$pin}else{$pin.Dispose()}
  }
  if($pins.Count -ne 1 -or !$pins[0].Alive){throw 'HOLD: exact current interactive explorer'}
  $p=$pins[0]
  return @{sid=$p.Sid;session=$p.Session;pid=$p.Pid;creationFileTime=[string]$p.CreationFileTime;logonHigh=[string]$p.LogonHigh;logonLow=[string]$p.LogonLow;path=$p.Path}
 }finally{foreach($p in $pins){$p.Dispose()}}
}
function Get-StockState([string]$Phonebook) {
 Assert-StockAncestors $Phonebook
 $selectedProfile=[StockProcessPin]::ReadSelectedProfile($Phonebook)
 $ras=& "$env:SystemRoot/System32/rasdial.exe" 2>&1
 if($LASTEXITCODE -ne 0 -or (($ras -join "`n").Trim()) -cne "No connections`nCommand completed successfully."){throw 'HOLD: RAS absence reader'}
 $sa=Get-StockSaCounts
 if($sa.main -ne 0 -or $sa.quick -ne 0){throw 'HOLD: SA active'}
 $scheduler=New-Object -ComObject Schedule.Service;$scheduler.Connect()
 $task=$scheduler.GetFolder('\').GetTask('BimeronStep8Probe')
 $policy=@(Get-ExecutionPolicy -List | ForEach-Object {@{scope=[string]$_.Scope;value=[string]$_.ExecutionPolicy}})
 return @{wrapper=(Get-StockHash ([IO.File]::ReadAllBytes('C:/BimeronStep8/probe.ps1')));context=(Get-StockContext);services=@(Get-StockServiceSnapshot);profile=@{phonebook=$Phonebook;selected=$selectedProfile};originalTask=@{xml=[string]$task.Xml;sddl=[string]$task.GetSecurityDescriptor(7);instances=@($task.GetInstances(0)|ForEach-Object {[string]$_.InstanceGuid})};policy=$policy;ras=0;main=$sa.main;quick=$sa.quick;rasReaderSucceeded=$true;saReaderSucceeded=$true}
}
function Pin-StockLauncher {
 $timer=[Diagnostics.Stopwatch]::StartNew()
 while(!(Test-Path -LiteralPath "$global:StockRoot/readiness.txt")){
  if($timer.Elapsed.TotalSeconds -ge 45){throw 'Readiness timeout'}
  Start-Sleep -Milliseconds 100
 }
 $global:StockReadinessBytes=[IO.File]::ReadAllBytes("$global:StockRoot/readiness.txt")
 $global:StockReadiness=Read-StockWire $global:StockReadinessBytes @('version','nonce','configSHA256','executableSHA256','pid','creationFileTime','SID','session','elevation','logonHigh','logonLow','phonebookMatches','profileAccepted')
 $global:StockPinAcquisition='Initiated'
 $global:StockPin=Open-StockPrivatePin ([int]$global:StockReadiness.pid)
 Assert-StockReadiness $global:StockReadiness $global:StockConfig (Get-StockHash $global:StockConfigBytes) $global:StockPin
 if($global:StockPin.Path -ine "$global:StockRoot\Launcher.exe" -or (Get-StockHash ([IO.File]::ReadAllBytes($global:StockPin.Path))) -cne $global:StockConfig.executableSHA256){throw 'Private image mismatch'}
 $instances=@($global:StockTask.GetInstances(0)|ForEach-Object {[string]$_.InstanceGuid})
 if($instances.Count -ne 1 -or $instances[0] -ine $global:StockInstanceId){throw 'Task instance mismatch'}
 $global:StockPinVerified=$true
 return @{readiness=[Convert]::ToBase64String($global:StockReadinessBytes);identity=@{pid=$global:StockPin.Pid;creationFileTime=[string]$global:StockPin.CreationFileTime;path=$global:StockPin.Path;sha256=$global:StockConfig.executableSHA256};instance=$global:StockInstanceId}
}
function Publish-StockPermit([long]$ExpiresUtcTicks) {
 Assert-StockReadiness $global:StockReadiness $global:StockConfig (Get-StockHash $global:StockConfigBytes) $global:StockPin
 $state=Get-StockState $global:StockConfig.expectedPhonebook
 if(($state.context|ConvertTo-Json -Compress) -cne ($global:StockBaseline.context|ConvertTo-Json -Compress)){throw 'Interactive context changed'}
 $remaining=$ExpiresUtcTicks-[DateTime]::UtcNow.Ticks
 if($remaining -le 0 -or $remaining -gt [TimeSpan]::FromSeconds(30).Ticks){throw 'Permit publication expired/skewed'}
 $bytes=New-StockPermit $global:StockConfig $global:StockReadiness (Get-StockHash $global:StockConfigBytes) (Get-StockHash $global:StockReadinessBytes) ($ExpiresUtcTicks-[TimeSpan]::FromSeconds(25).Ticks)
 Write-StockOnce "$global:StockRoot/permit.txt" $bytes
 return @{permitSHA256=(Get-StockHash $bytes);permit=[Convert]::ToBase64String($bytes)}
}
function Get-StockIdentity($Service) {return @{name=$Service.name;path=$Service.path;account=$Service.account;startMode=$Service.startMode}}
function Get-StockCohosts($Before) {
 $all=@(Get-CimInstance Win32_Service -ErrorAction Stop)
 return @($Before.cohosts|ForEach-Object {$name=$_.name;$s=@($all|Where-Object Name -IEQ $name);if($s.Count -ne 1){throw 'Cohost missing'};@{name=(Get-StockCanonicalServiceName $s[0].Name);state=$s[0].State;startMode=$s[0].StartMode;path=$s[0].PathName;account=$s[0].StartName}})
}
function Stop-StockOne([string]$Name) {
 if($Name -cnotin @('RasMan','EapHost','IKEEXT')){throw 'Service scope'}
 if($null -eq $global:StockStoppedServices){$global:StockStoppedServices=[ordered]@{}}
 if($global:StockStoppedServices.Contains($Name)){throw 'Stop already attempted'}
  $baseline=@($global:StockBaseline.services|Where-Object name -CEQ $name)[0]
  $result=Stop-StockService $name $baseline
  $cohostsBefore=@($result.before.cohosts|Where-Object name -INE $name)
  $cohostsAfter=@(Get-StockCohosts $result.before|Where-Object name -INE $name)
  if(($cohostsBefore|ConvertTo-Json -Depth 12 -Compress) -cne ($cohostsAfter|ConvertTo-Json -Depth 12 -Compress)){throw 'HOLD: cohost state changed'}
  $global:StockStoppedServices[$name]=@{state=$result.after.state;exitCode=$result.after.exitCode;serviceSpecificExitCode=$result.after.serviceSpecificExitCode;identityBefore=(Get-StockIdentity $result.before);identityAfter=(Get-StockIdentity $result.after);dependentsBefore=$result.before.dependents;dependentsAfter=$result.after.dependents;cohostsBefore=$cohostsBefore;cohostsAfter=$cohostsAfter}
 return $global:StockStoppedServices[$Name]
}
function Assert-StockC1($Proof) {
 $binding=$Proof.admission.Binding;$root='C:/BimeronFull300/'+$binding.Nonce
 foreach($name in @('live-admission.json','dial-once.json','cleanup.json')){if(Test-Path -LiteralPath "$root/$name"){throw 'C1 custom admission/cleanup collision'}}
 $status=Get-Content -LiteralPath "$root/gate-status.json" -Raw | ConvertFrom-Json
 foreach($key in @('SHA256','Nonce','PolicySHA256')){if($status.$key -cne $binding.$key){throw 'C1 binding'}}
 if($status.State -cne 'OBSERVING' -or $status.Completed300 -ne $true -or ($null -ne $status.Errors -and @($status.Errors).Count -gt 0)){throw 'C1 observing gate'}
 $owner=$Proof.owner
 $pin=[StockProcessPin]::new([int]$owner.pid)
 try {
  if(!$pin.Alive -or [string]$pin.CreationFileTime -cne $owner.creationFileTime -or $pin.Path -ine $owner.path -or (Get-StockHash ([IO.File]::ReadAllBytes($pin.Path))) -cne $binding.SHA256){throw 'C1 retained identity'}
 }finally{$pin.Dispose()}
}
function Assert-StockRestored($State) {
 foreach($key in @('context','profile','originalTask','wrapper','policy')){
  if(($State[$key]|ConvertTo-Json -Depth 20 -Compress) -cne ($global:StockBaseline[$key]|ConvertTo-Json -Depth 20 -Compress)){throw ('Restored '+$key+' changed')}
 }
 foreach($base in $global:StockBaseline.services){
  $current=@($State.services|Where-Object name -CEQ $base.name)
  if($current.Count -ne 1){throw 'Restored service missing'}
  foreach($key in @('state','path','account','startMode')){if($current[0][$key] -cne $base[$key]){throw 'Restored service changed'}}
  $cohosts=Get-StockCohosts $base
  if(($cohosts|ConvertTo-Json -Depth 12 -Compress) -cne ($base.cohosts|ConvertTo-Json -Depth 12 -Compress)){throw 'Restored cohost changed'}
 }
}
function Set-StockGuestPhaseInputs($Config,[byte[]]$Executable,[byte[]]$NativeSource) {
 if(Get-Variable StockPhase_Config -Scope Global -ErrorAction SilentlyContinue){throw 'Guest inputs already bound'}
 $global:StockPinVerified=$false
 $global:StockPinAcquisition='NeverInitiated'
 $global:StockPhase_Config=$Config;$global:StockPhase_Executable=$Executable;$global:StockPhase_NativeSource=$NativeSource
}
function Invoke-StockGuestPhase([string]$Name) {
 switch -CaseSensitive ($Name) {
 'baseline' {return Invoke-StockGuestStep 'baseline' {
 if($env:COMPUTERNAME -cne '<LAB_GUEST_NAME>'){throw 'Guest identity'}
 if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $global:StockPhase_Config.expectedSid -or !([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Retained administrative principal'}
 if(!('StockProcessPin' -as [type])){Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString($global:StockPhase_NativeSource)) -ErrorAction Stop}
 $global:StockPhase_context=Get-StockContext
 if($global:StockPhase_context.sid -cne $global:StockPhase_Config.expectedSid){throw 'SID mismatch'}
 $global:StockPhase_Config.expectedLogonHigh=$global:StockPhase_context.logonHigh;$global:StockPhase_Config.expectedLogonLow=$global:StockPhase_context.logonLow
 $global:StockStoppedServices=[ordered]@{}
 $global:StockBaseline=Get-StockState $global:StockPhase_Config.expectedPhonebook
 foreach($global:StockPhase_name in @('RemoteAccess','dot3svc','XboxNetApiSvc')){if(@($global:StockBaseline.services|Where-Object name -CEQ $global:StockPhase_name)[0].state -cne 'Stopped'){throw 'Active dependent workload'}}
 foreach($global:StockPhase_name in @('RasMan','EapHost','IKEEXT')){
  $global:StockPhase_service=@($global:StockBaseline.services|Where-Object name -CEQ $global:StockPhase_name)[0]
  if($global:StockPhase_service.state -cnotin @('Running','Stopped') -or ($global:StockPhase_service.state -ceq 'Running' -and !$global:StockPhase_service.canStop) -or @($global:StockPhase_service.dependents|Where-Object state -CNE 'Stopped').Count){throw 'Service preflight'}
 }
 if((Get-StockHash $global:StockPhase_Executable) -cne $global:StockPhase_Config.executableSHA256){throw 'Executable digest'}
 if($global:StockPhase_Config.nonce -cnotmatch '^[a-f0-9]{64}$'){throw 'Nonce schema'}

 } {
return @{baseline=$global:StockBaseline}
 }}
 'directory-parent' {return Invoke-StockGuestStep 'directory-parent' {
 $global:StockPhase_root='C:\BimeronStockUI\'+$global:StockPhase_Config.nonce
 if(Test-Path -LiteralPath $global:StockPhase_root){throw 'Exclusive run collision'}
 if(!(Test-Path -LiteralPath 'C:\BimeronStockUI')){Assert-StockAncestors 'C:\';$null=New-Item -ItemType Directory -Path 'C:\BimeronStockUI' -ErrorAction Stop}

 } {
return @{prepared=$true}
 }}
 'directory' {return Invoke-StockGuestStep 'directory' {
 Assert-StockAncestors (Split-Path $global:StockPhase_root)
 $null=New-Item -ItemType Directory -Path $global:StockPhase_root -ErrorAction Stop

 } {
return @{created=$true}
 }}
 'directory-acl' {return Invoke-StockGuestStep 'directory-acl' {
 $global:StockPhase_acl=[Security.AccessControl.DirectorySecurity]::new()
 $global:StockPhase_acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;'+$global:StockPhase_Config.expectedSid+')')
 Set-Acl -LiteralPath $global:StockPhase_root -AclObject $global:StockPhase_acl

 } {
 $global:StockAcl=(Get-Acl -LiteralPath $global:StockPhase_root).GetSecurityDescriptorBinaryForm()
 $global:StockConfig=$global:StockPhase_Config;$global:StockRoot=$global:StockPhase_root
 $global:StockConfigBytes=ConvertTo-StockWire $global:StockPhase_Config

return @{configured=$true}
 }}
 'config-file' {return Invoke-StockGuestStep 'config-file' {
 Write-StockOnce "$global:StockRoot/config.txt" $global:StockConfigBytes
 } {
return @{written=$true}
 }}
 'executable-file' {return Invoke-StockGuestStep 'executable-file' {
 Write-StockOnce "$global:StockRoot/Launcher.exe" $global:StockPhase_Executable
 } {
return @{written=$true}
 }}
 'scheduler-definition' {return Invoke-StockGuestStep 'scheduler-definition' {
 $global:StockPhase_svc=New-Object -ComObject Schedule.Service;$global:StockPhase_svc.Connect();$global:StockFolder=$global:StockPhase_svc.GetFolder('\')
 $global:StockPhase_name='BimeronStockUI-'+$global:StockPhase_Config.nonce
 if(@($global:StockFolder.GetTasks(1)|Where-Object Name -IEQ $global:StockPhase_name).Count){throw 'Task collision'}
 $global:StockPhase_d=$global:StockPhase_svc.NewTask(0);$global:StockPhase_d.Principal.UserId=$global:StockPhase_Config.expectedSid;$global:StockPhase_d.Principal.LogonType=3;$global:StockPhase_d.Principal.RunLevel=1
 $global:StockPhase_d.Settings.Enabled=$true;$global:StockPhase_d.Settings.AllowDemandStart=$true;$global:StockPhase_d.Settings.AllowHardTerminate=$false;$global:StockPhase_d.Settings.ExecutionTimeLimit='PT0S';$global:StockPhase_d.Settings.MultipleInstances=2
 $global:StockPhase_d.Settings.RestartCount=0;$global:StockPhase_d.Settings.DisallowStartIfOnBatteries=$false;$global:StockPhase_d.Settings.StopIfGoingOnBatteries=$false
 $global:StockPhase_action=$global:StockPhase_d.Actions.Create(0);$global:StockPhase_action.Path="$global:StockPhase_root/Launcher.exe";$global:StockPhase_action.Arguments='--run';$global:StockPhase_action.WorkingDirectory=$global:StockPhase_root

 } {
return @{prepared=$true}
 }}
 'task-registration' {return Invoke-StockGuestStep 'task-registration' {
 $global:StockTask=$global:StockFolder.RegisterTaskDefinition($global:StockPhase_name,$global:StockPhase_d,2,$global:StockPhase_Config.expectedSid,$null,3,'D:P(A;;GA;;;SY)(A;;GA;;;BA)')
 return $global:StockTask
 } {
 if(![object]::ReferenceEquals($args[0],$global:StockTask)){throw 'Registration ownership changed'}
 $global:StockTaskRegistration=@{xml=[string]$global:StockTask.Xml;sddl=[string]$global:StockTask.GetSecurityDescriptor(7)}
 if($global:StockTask.Definition.Triggers.Count -ne 0 -or $global:StockTask.Definition.Settings.RestartCount -ne 0 -or $global:StockTask.Definition.Settings.AllowHardTerminate){throw 'Task readback'}

return $global:StockTaskRegistration
 }}
 'task-start' {return Invoke-StockGuestStep 'task-start' {
 $global:StockInstance=$global:StockTask.Run($null)
 return $global:StockInstance
 } {
 if(![object]::ReferenceEquals($args[0],$global:StockInstance)){throw 'Instance ownership changed'}
 $global:StockInstanceId=[string]$global:StockInstance.InstanceGuid

return @{instance=$global:StockInstanceId}
 }}
 'deployment-result' {return Invoke-StockGuestStep 'deployment-result' {

 } {
 return @{baseline=$global:StockBaseline;config=$global:StockPhase_Config;configSHA256=(Get-StockHash $global:StockConfigBytes);acl=[Convert]::ToBase64String($global:StockAcl);task=$global:StockTaskRegistration;instance=$global:StockInstanceId}
 }}
 'quiescence' {return Invoke-StockGuestStep 'quiescence' {

 } {
 $global:StockPhase_services=$global:StockStoppedServices
 if($null -eq $global:StockPhase_services -or $global:StockPhase_services.Count -ne 3){throw 'All stopped proofs required'}
 $global:StockPhase_zero=Get-StockState $global:StockConfig.expectedPhonebook
 foreach($global:StockPhase_name in @('RasMan','EapHost','IKEEXT')){
  $global:StockPhase_current=@($global:StockPhase_zero.services|Where-Object name -CEQ $global:StockPhase_name)[0]
  if($global:StockPhase_current.state -cne 'Stopped' -or $global:StockPhase_current.exitCode -ne 0 -or $global:StockPhase_current.serviceSpecificExitCode -ne 0 -or $global:StockPhase_current.pid -ne 0 -or @($global:StockPhase_current.dependents|Where-Object state -CNE 'Stopped').Count){throw 'Quiescence changed before retirement'}
 }
 foreach($global:StockPhase_name in @('BFE','PolicyAgent')){
  $global:StockPhase_before=@($global:StockBaseline.services|Where-Object name -CEQ $global:StockPhase_name)[0];$global:StockPhase_after=@($global:StockPhase_zero.services|Where-Object name -CEQ $global:StockPhase_name)[0]
  foreach($global:StockPhase_key in @('state','path','startMode','account')){if($global:StockPhase_before[$global:StockPhase_key] -cne $global:StockPhase_after[$global:StockPhase_key]){throw 'Protected service changed before retirement'}}
 }

return $global:StockPhase_zero
 }}
 'private-retirement' {return Invoke-StockGuestStep 'private-retirement' {
 $global:StockPhase_identity=@{pid=$global:StockPin.Pid;creationFileTime=[string]$global:StockPin.CreationFileTime;path=$global:StockPin.Path;sha256=$global:StockConfig.executableSHA256}
 $global:StockPhase_calls=0
 if($global:StockPin.Alive){$global:StockPhase_calls=1;$global:StockPin.Retire()}

 } {
 if($global:StockPin.Alive){throw 'HOLD: private exit'}
 $global:StockPhase_private=@{handleRetainedBeforePermit=$true;signalled=$true;identityBefore=$global:StockPhase_identity;identityAfter=$global:StockPhase_identity;terminateCalls=$global:StockPhase_calls;exitCode=$global:StockPin.ExitCode}

return $global:StockPhase_private
 }}
 'raw-result' {return Invoke-StockGuestStep 'raw-result' {

 } {
 $global:StockPhase_outcome=@{state='unknown'}
 if(Test-Path -LiteralPath "$global:StockRoot/result.txt"){
  $global:StockPhase_bytes=[IO.File]::ReadAllBytes("$global:StockRoot/result.txt")
  $global:StockPhase_r=Read-StockWire $global:StockPhase_bytes @('version','nonce','configSHA256','readinessSHA256','executableSHA256','reviewSHA256','permitSHA256','entryUtcTicks','returnUtcTicks','BOOL','dwError')
  foreach($global:StockPhase_k in @('nonce','executableSHA256','reviewSHA256')){if($global:StockPhase_r[$global:StockPhase_k] -cne $global:StockConfig[$global:StockPhase_k]){throw 'Result binding'}}
  if($global:StockPhase_r.version -cne '2' -or $global:StockPhase_r.configSHA256 -cne (Get-StockHash $global:StockConfigBytes) -or $global:StockPhase_r.readinessSHA256 -cne (Get-StockHash $global:StockReadinessBytes) -or $global:StockPhase_r.permitSHA256 -cne (Get-StockHash ([IO.File]::ReadAllBytes("$global:StockRoot/permit.txt")))){throw 'Result hash binding'}
  Assert-StockDecimal $global:StockPhase_r.BOOL 1;Assert-StockDecimal $global:StockPhase_r.dwError ([uint32]::MaxValue)
  Assert-StockDecimal $global:StockPhase_r.entryUtcTicks ([long]::MaxValue);Assert-StockDecimal $global:StockPhase_r.returnUtcTicks ([long]::MaxValue)
  if([long]$global:StockPhase_r.returnUtcTicks -lt [long]$global:StockPhase_r.entryUtcTicks){throw 'Result time order'}
  $global:StockPhase_outcome=@{state='returned';BOOL=[int]$global:StockPhase_r.BOOL;dwError=[uint32]$global:StockPhase_r.dwError;wire=[Convert]::ToBase64String($global:StockPhase_bytes);nonce=$global:StockPhase_r.nonce}
 }

return $global:StockPhase_outcome
 }}
 'task-exit' {return Invoke-StockGuestStep 'task-exit' {

 } {
 $global:StockPhase_timer=[Diagnostics.Stopwatch]::StartNew()
 do {
  $global:StockPhase_instances=@($global:StockTask.GetInstances(0)|ForEach-Object {[string]$_.InstanceGuid})
  if(@($global:StockPhase_instances|Where-Object {$_ -ine $global:StockInstanceId}).Count){throw 'Unknown task instance'}
  if($global:StockPhase_instances.Count -eq 0 -and $global:StockTask.State -eq 3){break}
  Start-Sleep -Milliseconds 100
 }while($global:StockPhase_timer.Elapsed.TotalSeconds -lt 30)
 if($global:StockPhase_instances.Count -ne 0 -or $global:StockTask.State -ne 3){throw 'Task exit unresolved'}
 $global:StockPhase_registration=@{xml=[string]$global:StockTask.Xml;sddl=[string]$global:StockTask.GetSecurityDescriptor(7)}
 if(($global:StockPhase_registration|ConvertTo-Json -Compress) -cne ($global:StockTaskRegistration|ConvertTo-Json -Compress)){throw 'Task registration changed'}

return @{instance=$global:StockInstanceId;registration=$global:StockPhase_registration}
 }}
 'task-delete' {return Invoke-StockGuestStep 'task-delete' {
 $global:StockFolder.DeleteTask($global:StockTask.Name,0)
 } {
 if(@($global:StockFolder.GetTasks(1)|Where-Object Name -CEQ ('BimeronStockUI-'+$global:StockConfig.nonce)).Count){throw 'Task deletion unproven'}
 $global:StockPhase_task=@{instances=@();registrationDeleted=$true;registrationBefore=$global:StockTaskRegistration;registrationAtDelete=$global:StockPhase_registration;instance=$global:StockInstanceId}

return $global:StockPhase_task
 }}
 'restore-IKEEXT' {return Invoke-StockGuestStep 'restore-IKEEXT' {
 $global:StockPhase_name='IKEEXT'
  $global:StockPhase_base=@($global:StockBaseline.services|Where-Object name -CEQ $global:StockPhase_name)[0]
  if($global:StockPhase_base.state -ceq 'Running'){
   $global:StockPhase_svc=Get-Service -Name $global:StockPhase_name -ErrorAction Stop
   if(@($global:StockPhase_svc.ServicesDependedOn|Where-Object Status -NE 'Running').Count){throw 'Restore would start dependency'}
   $global:StockPhase_svc.Start()
  }elseif($global:StockPhase_base.state -cne 'Stopped'){throw 'Unsupported baseline state'}

 } {
if($global:StockPhase_base.state -ceq 'Running'){$global:StockPhase_svc.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(30))}
return @{service=$global:StockPhase_name;state=$global:StockPhase_base.state}
 }}
 'restore-EapHost' {return Invoke-StockGuestStep 'restore-EapHost' {
 $global:StockPhase_name='EapHost'
  $global:StockPhase_base=@($global:StockBaseline.services|Where-Object name -CEQ $global:StockPhase_name)[0]
  if($global:StockPhase_base.state -ceq 'Running'){
   $global:StockPhase_svc=Get-Service -Name $global:StockPhase_name -ErrorAction Stop
   if(@($global:StockPhase_svc.ServicesDependedOn|Where-Object Status -NE 'Running').Count){throw 'Restore would start dependency'}
   $global:StockPhase_svc.Start()
  }elseif($global:StockPhase_base.state -cne 'Stopped'){throw 'Unsupported baseline state'}

 } {
if($global:StockPhase_base.state -ceq 'Running'){$global:StockPhase_svc.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(30))}
return @{service=$global:StockPhase_name;state=$global:StockPhase_base.state}
 }}
 'restore-RasMan' {return Invoke-StockGuestStep 'restore-RasMan' {
 $global:StockPhase_name='RasMan'
  $global:StockPhase_base=@($global:StockBaseline.services|Where-Object name -CEQ $global:StockPhase_name)[0]
  if($global:StockPhase_base.state -ceq 'Running'){
   $global:StockPhase_svc=Get-Service -Name $global:StockPhase_name -ErrorAction Stop
   if(@($global:StockPhase_svc.ServicesDependedOn|Where-Object Status -NE 'Running').Count){throw 'Restore would start dependency'}
   $global:StockPhase_svc.Start()
  }elseif($global:StockPhase_base.state -cne 'Stopped'){throw 'Unsupported baseline state'}

 } {
if($global:StockPhase_base.state -ceq 'Running'){$global:StockPhase_svc.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(30))}
return @{service=$global:StockPhase_name;state=$global:StockPhase_base.state}
 }}
 'restoration-result' {return Invoke-StockGuestStep 'restoration-result' {

 } {
 $global:StockPhase_restored=Get-StockState $global:StockConfig.expectedPhonebook
 foreach($global:StockPhase_key in @('context','profile','originalTask','wrapper','policy')){if(($global:StockPhase_restored[$global:StockPhase_key]|ConvertTo-Json -Depth 20 -Compress) -cne ($global:StockBaseline[$global:StockPhase_key]|ConvertTo-Json -Depth 20 -Compress)){throw ('Restore mismatch '+$global:StockPhase_key)}}
 foreach($global:StockPhase_base in $global:StockBaseline.services){
  $global:StockPhase_cohosts=Get-StockCohosts $global:StockPhase_base
  if(($global:StockPhase_cohosts|ConvertTo-Json -Depth 12 -Compress) -cne ($global:StockPhase_base.cohosts|ConvertTo-Json -Depth 12 -Compress)){throw 'Restored cohost baseline mismatch'}
  $global:StockPhase_actual=@($global:StockPhase_restored.services|Where-Object name -CEQ $global:StockPhase_base.name)[0]
  foreach($global:StockPhase_key in @('state','startMode','path','account')){if($global:StockPhase_actual[$global:StockPhase_key] -cne $global:StockPhase_base[$global:StockPhase_key]){throw 'Service baseline restoration mismatch'}}
 }
 return @{stoppedServices=$global:StockPhase_services;zero=$global:StockPhase_zero;privateExit=$global:StockPhase_private;taskClosure=$global:StockPhase_task;restored=$global:StockPhase_restored;outcome=$global:StockPhase_outcome;baseline=$global:StockBaseline}
 }}
 'stop-RasMan' {return Invoke-StockGuestStep 'stop-RasMan' {} {Stop-StockOne 'RasMan'}}
 'stop-EapHost' {return Invoke-StockGuestStep 'stop-EapHost' {} {Stop-StockOne 'EapHost'}}
 'stop-IKEEXT' {return Invoke-StockGuestStep 'stop-IKEEXT' {} {Stop-StockOne 'IKEEXT'}}
 default {throw 'Guest phase outside fixed disposition interface'}
 }
}
function Complete-StockGuestHandleRelease([string]$AcknowledgedExitSHA256) {
 if(!$global:StockGuestPhases.ContainsKey('private-retirement')){throw 'Private retirement evidence missing'}
 $record=$global:StockGuestPhases['private-retirement']
 if($record.verification -cne 'Verified'){throw 'Private retirement unverified'}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record.result|ConvertTo-Json -Depth 20 -Compress))
 if($AcknowledgedExitSHA256 -cne (Get-StockPrivateExitHash $record.result)){throw 'Private exit acknowledgement mismatch'}
 $record.acknowledged=$true
 return Invoke-StockGuestStep 'handle-release' {
  $global:StockPin.Dispose()
  return @{released=$true;exitSHA256=$AcknowledgedExitSHA256}
 } {param($released)return $released}
}
function Assert-StockNoPermitGuest {
 if($global:StockPinAcquisition -cne 'NeverInitiated'){throw 'No-permit unpinned branch excludes pin acquisition'}
 foreach($name in @('task-registration','task-start')){
  if(!$global:StockGuestPhases.ContainsKey($name) -or $global:StockGuestPhases[$name].submission -cne 'Returned' -or $global:StockGuestPhases[$name].verification -cne 'Verified'){throw 'No-permit original deployment ownership missing'}
 }
 if($null -eq $global:StockTask -or $null -eq $global:StockInstance -or !$global:StockInstanceId){throw 'No-permit original instance missing'}
 foreach($name in @('permit.txt','attempt','result.txt')){if(Test-Path -LiteralPath (Join-Path $global:StockRoot $name)){throw 'Unexpected no-permit marker'}}
 Assert-StockAncestors $global:StockRoot
 if((Get-StockHash ([IO.File]::ReadAllBytes("$global:StockRoot/Launcher.exe"))) -cne $global:StockConfig.executableSHA256){throw 'No-permit launcher changed'}
 if((Get-StockHash ([IO.File]::ReadAllBytes("$global:StockRoot/config.txt"))) -cne (Get-StockHash $global:StockConfigBytes)){throw 'No-permit configuration changed'}
 if([Convert]::ToBase64String((Get-Acl -LiteralPath $global:StockRoot).GetSecurityDescriptorBinaryForm()) -cne [Convert]::ToBase64String($global:StockAcl)){throw 'No-permit ACL changed'}
 if($global:StockTask.Definition.Triggers.Count -ne 0 -or $global:StockTask.Definition.Settings.RestartCount -ne 0 -or $global:StockTask.Definition.Settings.AllowHardTerminate){throw 'No-permit task restart settings'}
 $registration=@{xml=[string]$global:StockTask.Xml;sddl=[string]$global:StockTask.GetSecurityDescriptor(7)}
 if(($registration|ConvertTo-Json -Compress) -cne ($global:StockTaskRegistration|ConvertTo-Json -Compress)){throw 'No-permit registration changed'}
 $instances=@($global:StockTask.GetInstances(0))
 if($instances.Count -ne 0 -or $global:StockTask.State -ne 3 -or [string]$global:StockInstance.InstanceGuid -ine $global:StockInstanceId){throw 'Original no-permit task not naturally complete'}
 $state=Get-StockState $global:StockConfig.expectedPhonebook
 Assert-StockRestored $state
 return @{pinAcquisitionNeverInitiated=$true;permitMarkersAbsent=$true;registration=$registration;instance=$global:StockInstanceId;naturalCompletion=$true;restartDisabled=$true;launcherSHA256=$global:StockConfig.executableSHA256;configSHA256=(Get-StockHash $global:StockConfigBytes);baseline=$global:StockBaseline;state=$state}
}
function Repair-StockGuestPhase([string]$Name) {
 if($Name.StartsWith('stop-')){$nested='scm-'+$Name;if(!$global:StockGuestPhases.ContainsKey($nested) -or $global:StockGuestPhases[$nested].submission -cne 'Returned'){throw 'Original SCM mutation not positively returned'}}
 if(!$global:StockGuestPhases.ContainsKey($Name) -or $global:StockGuestPhases[$Name].submission -cne 'Returned'){throw 'Guest phase cannot reconcile unknown mutation'}
 return Invoke-StockGuestPhase $Name
}
function Get-StockPrivateExitHash($Evidence) {
 $identities=@()
 foreach($name in @('identityBefore','identityAfter')){
  $v=$Evidence[$name]
  $identities+=,[ordered]@{pid=$v.pid;creationFileTime=$v.creationFileTime;path=$v.path;sha256=$v.sha256}
 }
 $ordered=[ordered]@{handleRetainedBeforePermit=$Evidence.handleRetainedBeforePermit;signalled=$Evidence.signalled;identityBefore=$identities[0];identityAfter=$identities[1];terminateCalls=$Evidence.terminateCalls;exitCode=$Evidence.exitCode}
 return Get-StockHash ([Text.UTF8Encoding]::new($false).GetBytes(($ordered|ConvertTo-Json -Depth 20 -Compress)))
}

function Open-StockPrivatePin([int]$ProcessId) {return [StockProcessPin]::new($ProcessId,$true)}
function Get-StockDispositionOwnership {
 if($global:StockPinAcquisition -ceq 'NeverInitiated'){return @{state='NeverInitiated'}}
 if(!$global:StockPinVerified -or $null -eq $global:StockPin){throw 'Initiated pin ownership unproven'}
 return @{state='OwnedVerified';identity=@{pid=$global:StockPin.Pid;creationFileTime=[string]$global:StockPin.CreationFileTime;path=$global:StockPin.Path;sha256=$global:StockConfig.executableSHA256}}
}
function Read-StockRestoredState {
 $state=Get-StockState $global:StockConfig.expectedPhonebook
 Assert-StockRestored $state
 return $state
}
