function Get-StockControllerPhases {
 return @(
@{name='phase-000';body={
$originalNic=Get-StockNic
}}
@{name='phase-001';body={
$originalSwitch=@{Id=$originalNic.SwitchId;SwitchType=$originalNic.SwitchType}
if([string]$originalSwitch.Id -ine '<LAB_VSWITCH_ID>'){throw 'Original switch identity'}
}}
@{name='phase-002';body={
if(!$originalNic.Connected -or [string]$originalNic.SwitchId -ine [string]$originalSwitch.Id -or [string]$originalSwitch.SwitchType -cne 'Private'){throw 'Original private topology'}
}}
@{name='phase-003';body={
$null=Save-Stock 'nic-original' @{id=[string]$originalNic.Id;mac=[string]$originalNic.MacAddress;switchId=[string]$originalSwitch.Id;switchType=[string]$originalSwitch.SwitchType;connected=$true}
}}
@{name='phase-004';body={
if($sessionAttempted){throw 'Original session submission unknown; replacement forbidden'}
$sessionAttempted=$true
$session=Open-OwnerSession
}}
@{name='phase-005';body={
$sources=@('stock-wire.ps1','stock-service-operations.ps1','stock-guest.ps1')|ForEach-Object {[IO.File]::ReadAllText((Join-Path $PSScriptRoot $_))}
}}
@{name='phase-006';body={
$null=Call-Stock {param($sources)foreach($source in $sources){. ([scriptblock]::Create(($source -replace '(?m)^function ', 'function global:')))}} @(,$sources) 15
}}
@{name='phase-007';body={
$config=[ordered]@{version='2';nonce=$nonce;expectedSid='<LAB_GUEST_SID_1001>';expectedSession='2';expectedLogonHigh='0';expectedLogonLow='0';expectedPhonebook=$c.phonebook;executableSHA256=$c.launcherSHA256;reviewSHA256=$c.reviewSHA256}
}}
@{name='phase-008';body={
Assert-StockHumanCurrent $root $ready
}}
@{name='phase-009';body={
& $script:StockPython "$PSScriptRoot/stock-check-protection.py" $ProofPath deployment
if($LASTEXITCODE -ne 0){throw 'Current protection failed'}
}}
@{name='phase-010';body={
$null=$null
}}
@{name='phase-011';body={
$null=Save-Stock 'deployment-intent' @{launcherSHA256=$c.launcherSHA256}
}}
@{name='phase-012';body={
$deployed=$true
}}
@{name='phase-013';body={
$null=Call-Stock {param($config,$exe,$source,$proof)Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString($source));Assert-StockC1 $proof;Set-StockGuestPhaseInputs $config $exe $source} @($config,$exe,[IO.File]::ReadAllBytes("$PSScriptRoot/StockProcessPin.cs"),$proof) 30 $false 'guest-inputs'
foreach($guestPhase in @('baseline','directory-parent','directory','directory-acl','config-file','executable-file','scheduler-definition','task-registration','task-start','deployment-result')){
 $init=Call-Stock {param($name)Invoke-StockGuestPhase $name} @($guestPhase) 30 $true $guestPhase
}
}}
@{name='phase-014';body={
$null=Save-Stock 'deployment-result' $init
}}
@{name='phase-015';body={
$pin=Call-Stock {Pin-StockLauncher} @() 50 $false 'pin'
}}
@{name='phase-016';body={
$null=Save-Stock 'readiness' $pin
}}
@{name='phase-017';body={
Assert-StockHumanCurrent $root $ready
}}
@{name='phase-018';body={
& $script:StockPython "$PSScriptRoot/stock-check-protection.py" $ProofPath permit
if($LASTEXITCODE -ne 0){throw 'Current protection failed'}
}}
@{name='phase-019';body={
$null=$null
}}
@{name='phase-020';body={
$null=Call-Stock {param($proof)Assert-StockC1 $proof} @($proof) 10
}}
@{name='phase-021';body={
Assert-StockHumanCurrent $root $ready
}}
@{name='phase-022';body={
$null=Save-Stock 'permit-intent' @{readinessSHA256=(Get-StockHash ([Convert]::FromBase64String($pin.readiness)))}
}}
@{name='phase-023';body={
$permitExpires=[DateTime]::UtcNow.AddSeconds(25).Ticks
}}
@{name='phase-024';body={
$deadline=[Diagnostics.Stopwatch]::StartNew()
}}
@{name='phase-025';body={
$script:Controller.permitSubmission='Initiated'
$permit=Start-StockGuestOperation $session {param($expires)Publish-StockPermit $expires} @($permitExpires) $true
$script:Controller.operations['permit']=$permit
}}
@{name='phase-026';body={
$operations+=,$permit
}}
@{name='phase-027';body={
while($deadline.Elapsed.TotalSeconds -lt 60 -and $permit.job.State -in @('Running','NotStarted','Blocked')){

  if(Test-Path -LiteralPath "$root/stock-human-revoked.json"){break};Start-Sleep -Milliseconds 25

 }
}}
@{name='phase-028';body={
if($permit.job.State -eq 'Completed' -and $deadline.Elapsed.TotalSeconds -lt 60 -and !(Test-Path -LiteralPath "$root/stock-human-revoked.json")){

  $pr=Complete-StockGuestOperation $permit 1;$null=Save-Stock 'permit-result' $pr

  do {

   $read=Start-StockGuestOperation $session {@{returned=(Test-Path -LiteralPath "$global:StockRoot/result.txt");live=$global:StockPin.Alive}} @() $false;$operations+=,$read

   while($deadline.Elapsed.TotalSeconds -lt 60 -and $read.job.State -in @('Running','NotStarted','Blocked')){if(Test-Path -LiteralPath "$root/stock-human-revoked.json"){break};Start-Sleep -Milliseconds 25}

   if($deadline.Elapsed.TotalSeconds -ge 60 -or (Test-Path -LiteralPath "$root/stock-human-revoked.json")){break}

   $sample=Complete-StockGuestOperation $read 1

   if($sample.returned -or !$sample.live){break}

   Start-Sleep -Milliseconds 100

  }while($deadline.Elapsed.TotalSeconds -lt 60)



 }
}}
@{name='phase-029';body={
$null=Save-Stock 'isolation-intent' @{deadlineElapsedMilliseconds=$(if($null -ne $deadline){$deadline.ElapsedMilliseconds}else{0})}
}}
@{name='phase-030';body={
$isolationAttempted=$true
}}
@{name='phase-031';body={
$isolation=Invoke-StockOwnedNic $script:Controller disconnect $originalNic
}}
@{name='phase-032';body={
$isolated=$true
}}
@{name='phase-033';body={
$isolationRef=Save-Stock 'isolation' $isolation
}}
@{name='phase-034';body={
$lateIndex=0
}}
@{name='phase-035';body={
foreach($op in @($script:StockSubmittedOperations)){
 if($op.ContainsKey('kind') -and $op.kind -ceq 'host-nic'){if(!$op.resolved){throw 'Outstanding host NIC operation'};continue}
 if(!$op.resolved){
  try{$late=Complete-StockGuestOperation $op 0}catch{
   if($op.collection -cne 'Collected' -or $op.terminal -cne 'Failed'){throw}
   if(![object]::ReferenceEquals($op,$permit) -and $op.mutation){throw 'Failed original mutation needs phase reconciliation'}
   # Full disposition must later prove settlement of this failed observation/permit.
  }
 }
}
}}
@{name='phase-036';body={
if($script:Controller.permitSubmission -ceq 'NeverInitiated'){
 $ownership=Call-Stock {Get-StockDispositionOwnership} @() 15 $false 'disposition-ownership'
 Select-StockDispositionBranch $script:Controller $ownership
}
$null=Save-Stock 'disposition-intent' @{isolated=$true}
}}
@{name='phase-037';body={
if(!$script:Controller.noPermit){
 foreach($name in @('RasMan','EapHost','IKEEXT')){
  $null=Save-Stock ('stop-'+$name.ToLowerInvariant()+'-intent') @{service=$name}
  $result=Call-Stock {param($name)Invoke-StockGuestPhase $name} @(('stop-'+$name)) 30 $true ('stop-'+$name)
  $null=Save-Stock ('stop-'+$name.ToLowerInvariant()+'-result') $result
 }
}
}}
@{name='phase-038';body={
if($script:Controller.noPermit){
 $noPermitEvidence=Call-Stock {Assert-StockNoPermitGuest} @() 30 $false 'no-permit-evidence'
 if($script:Controller.operations.ContainsKey('pin')){
  $pinOp=$script:Controller.operations['pin']
  if(!$pinOp.resolved -and $pinOp.collection -ceq 'Collected' -and $pinOp.terminal -ceq 'Failed' -and $noPermitEvidence.pinAcquisitionNeverInitiated -eq $true){$pinOp.reconciliation=@{kind='no-permit-natural-completion';evidence=$noPermitEvidence;originalFailed=$true};$pinOp.resolved=$true}
 }
 $ledger=Assert-StockNoPermitLedger $script:Controller
 $null=Call-Stock {param($name)Invoke-StockGuestPhase $name} @('task-exit') 30 $false 'task-exit'
 $taskClosure=Call-Stock {param($name)Invoke-StockGuestPhase $name} @('task-delete') 30 $true 'task-delete'
 $restoredState=Call-Stock {Read-StockRestoredState} @() 30 $false 'no-permit-restored'
 $admin=@{baseline=$noPermitEvidence.baseline;restored=$restoredState;taskClosure=$taskClosure;outcome=@{state='unknown'}}
 $noPermitEvidence.ownerLedger=$ledger
}else{
 foreach($guestPhase in @('quiescence','private-retirement','raw-result','task-exit','task-delete','restore-IKEEXT','restore-EapHost','restore-RasMan','restoration-result')){
  $admin=Call-Stock {param($name)Invoke-StockGuestPhase $name} @($guestPhase) 30 $true $guestPhase
 }
}
}}
@{name='phase-039';body={
$null=Save-Stock 'disposition-result' $admin
}}
@{name='phase-040';body={
if(!$script:Controller.noPermit){$stopped=Zero-Stock $admin.zero $admin.baseline}
}}
@{name='phase-041';body={
if(!$script:Controller.noPermit){$stopped.services=$admin.stoppedServices}
}}
@{name='phase-042';body={
if($script:Controller.noPermit){
 $refs=@{isolation=$isolationRef;deployment=(Save-Stock 'no-permit-deployment' $noPermitEvidence);taskClosure=(Save-Stock 'task-closure' $admin.taskClosure)}
}else{$refs=@{isolation=$isolationRef;stopped=(Save-Stock 'stopped' $stopped);privateExit=(Save-Stock 'private-exit' $admin.privateExit);taskClosure=(Save-Stock 'task-closure' $admin.taskClosure)} }
# Failed original permit/observation is settled only by the concrete full disposition.
if(!$script:Controller.noPermit){
 foreach($op in $script:StockSubmittedOperations){
  if(!$op.resolved -and $op.collection -ceq 'Collected' -and $op.terminal -ceq 'Failed' -and [object]::ReferenceEquals($op,$permit)){
   $op.reconciliation=@{kind='administrative-disposition';stopped=$refs.stopped;privateExit=$refs.privateExit;taskClosure=$refs.taskClosure;originalFailed=$true}
   $op.resolved=$true
  }
 }
}
}}
@{name='phase-043';body={
$restored=Zero-Stock $admin.restored $admin.baseline
}}
@{name='phase-044';body={
foreach($key in @('context','profile','originalTask','wrapper','policy')){$restored[$key+'Before']=$admin.baseline[$key];$restored[$key+'After']=$admin.restored[$key]}
}}
@{name='phase-045';body={
$restored.servicesBefore=@($admin.baseline.services|ForEach-Object {@{identity=(Get-StockIdentity $_);state=$_.state}})
}}
@{name='phase-046';body={
$restored.servicesAfter=@($admin.restored.services|ForEach-Object {@{identity=(Get-StockIdentity $_);state=$_.state}})
}}
@{name='phase-047';body={
$refs.restored=Save-Stock 'restored' $restored
}}
@{name='phase-048';body={
$nic=Get-StockNic
}}
@{name='phase-049';body={
if($nic.Connected){throw 'NIC unexpectedly connected'}
}}
@{name='phase-050';body={
$nr=Zero-Stock $admin.restored $admin.baseline
}}
@{name='phase-051';body={
$nr.connected=$false
}}
@{name='phase-052';body={
$nr.id=[string]$nic.Id
}}
@{name='phase-053';body={
$nr.mac=[string]$nic.MacAddress
}}
@{name='phase-054';body={
$nr.switchId=''
}}
@{name='phase-055';body={
$refs.nic=Save-Stock 'nic-isolated' $nr
}}
@{name='phase-056';body={
$outcome=$admin.outcome
}}
@{name='phase-057';body={
if($outcome.state -ceq 'returned'){$rawRef=Save-Stock 'raw-result' $outcome;$outcome=@{state='returned';BOOL=$outcome.BOOL;dwError=$outcome.dwError;result=$rawRef}}
}}
@{name='phase-058';body={
Complete-StockPendingPublications $script:Controller $root
$operationJournal=Save-Stock 'operation-journal-precleanup' (Get-StockOperationEvidence $script:Controller)
foreach($ownedOp in $script:StockSubmittedOperations){$ownedOp.publication='Published';$ownedOp.publicationEvidence=$operationJournal}
$journal=@{}
}}
@{name='phase-059';body={
foreach($file in @(Get-ChildItem -LiteralPath $root -Filter '*.json')){$bytes=[IO.File]::ReadAllBytes($file.FullName);$journal[$file.BaseName]=@{name=$file.Name;sha256=(Get-StockHash $bytes);length=$bytes.Length}}
}}
@{name='phase-060';body={
$pre=@{schema=$(if($script:Controller.noPermit){'stock-no-permit-precleanup-v1'}else{'stock-admin-precleanup-v1'});normalCleanupSucceeded=$false;rawUiOutcome=$outcome;references=$refs;journal=$journal}
}}
@{name='phase-061';body={
Assert-StockContinuingProtection $ProofPath
$preRef=Save-Stock 'precleanup' $pre
}}
@{name='phase-062';body={
$timer=[Diagnostics.Stopwatch]::StartNew()
}}
@{name='phase-063';body={
if(!(Test-Path -LiteralPath "$root/finalize-request.json")){
 if($timer.Elapsed.TotalSeconds -ge 300){throw 'C1 finalization wait expired; original owner retained'}
 $script:Controller.status='WaitingForFinalization';return
}
}}
@{name='phase-064';body={
$request=Assert-StrictOwnerJson ([IO.File]::ReadAllBytes("$root/finalize-request.json"))
}}
@{name='phase-065';body={
Assert-OwnerFields $request @('schema','nonce','binding','precleanup','c1','guardSHA256','captureHealthy')
}}
@{name='phase-066';body={
if($request.schema -cne 'stock-finalize-request-v1' -or $request.nonce -cne $nonce -or $request.precleanup.sha256 -cne $preRef.sha256 -or $request.guardSHA256 -cne $proof.admission.GuardSHA256 -or $request.captureHealthy -isnot [bool] -or !$request.captureHealthy){throw 'Finalize request binding'}
}}
@{name='phase-067';body={
$c1raw=[IO.File]::ReadAllBytes("$root/c1.json")
}}
@{name='phase-068';body={
if($request.c1.sha256 -cne (Get-StockHash $c1raw) -or $request.c1.length -ne $c1raw.Length){throw 'C1 reference'}
}}
@{name='phase-069';body={
$c1=Assert-StrictOwnerJson $c1raw
}}
@{name='phase-070';body={
if($c1.status -cne 'PASS' -or !$c1.rasAbsent -or !$c1.ownerAbsent -or !$c1.taskReady -or $c1.nonce -cne $nonce){throw 'C1 independent absence'}
}}
@{name='phase-071';body={
$n=Get-StockNic
}}
@{name='phase-072';body={
if($n.Connected){throw 'NIC changed before reconnect'}
}}
@{name='phase-073';body={
$before=Call-Stock {Read-StockRestoredState} @() 15 $false 'before-reconnect'
}}
@{name='phase-074';body={
$null=Zero-Stock $before $admin.baseline
}}
@{name='phase-075';body={
$null=Save-Stock 'reconnect-intent' @{id=[string]$n.Id;switchId='<LAB_VSWITCH_ID>'}
}}
@{name='phase-076';body={
# Exact private switch is checked inside the retained NIC mutation runspace.
$null=$null
}}
@{name='phase-077';body={
$null=$null
}}
@{name='phase-078';body={
$reconnectAttempted=$true
}}
@{name='phase-079';body={
Assert-StockContinuingProtection $ProofPath
$null=Invoke-StockOwnedNic $script:Controller reconnect $originalNic
}}
@{name='phase-080';body={
$n=Get-StockNic
}}
@{name='phase-081';body={
if(!$n.Connected -or [string]$n.SwitchId -ine '<LAB_VSWITCH_ID>'){throw 'Reconnect unproven'}
}}
@{name='phase-082';body={
$after=Call-Stock {Read-StockRestoredState} @() 15 $false 'after-reconnect'
}}
@{name='phase-083';body={
foreach($key in @('context','profile','originalTask','wrapper','policy')){if(($before[$key]|ConvertTo-Json -Depth 20 -Compress) -cne ($after[$key]|ConvertTo-Json -Depth 20 -Compress)){throw 'Post reconnect state changed'}}
}}
@{name='phase-084';body={
$nr=Zero-Stock $after $admin.baseline
}}
@{name='phase-085';body={
$nr.connected=$true
}}
@{name='phase-086';body={
$nr.id=[string]$n.Id
}}
@{name='phase-087';body={
$nr.mac=[string]$n.MacAddress
}}
@{name='phase-088';body={
$nr.switchId=[string]$n.SwitchId
}}
@{name='phase-089';body={
$finalRefs=$refs.Clone()
}}
@{name='phase-090';body={
$finalRefs.nic=Save-Stock 'nic-restored' $nr
}}
@{name='phase-091';body={
$finalRefs.precleanup=$preRef
}}
@{name='phase-092';body={
$finalRefs.c1=$request.c1
}}
@{name='phase-093';body={
if(!$script:Controller.noPermit){
 $ack=Get-StockPrivateExitHash $admin.privateExit
 $release=Call-Stock {param($ack)Complete-StockGuestHandleRelease $ack} @($ack) 15 $true 'handle-release'
 $releaseReference=Save-Stock 'handle-release' $release
 $script:Controller.operations['handle-release'].publication='Published';$script:Controller.operations['handle-release'].publicationEvidence=$releaseReference
}
$closed=Close-StockSession $session $script:StockSubmittedOperations
}}
@{name='phase-094';body={
$session=$null
}}
@{name='phase-095';body={
$finalRefs.session=Save-Stock 'session-closed' $closed
}}
@{name='phase-096';body={
$null=Save-Stock 'operation-journal-final' (Get-StockOperationEvidence $script:Controller)
$finalJournal=@{}
}}
@{name='phase-097';body={
foreach($file in @(Get-ChildItem -LiteralPath $root -Filter '*.json')){$bytes=[IO.File]::ReadAllBytes($file.FullName);$finalJournal[$file.BaseName]=@{name=$file.Name;sha256=(Get-StockHash $bytes);length=$bytes.Length}}
}}
@{name='phase-098';body={
$null=Save-Stock 'final' @{schema=$(if($script:Controller.noPermit){'stock-no-permit-receipt-v1'}else{'stock-admin-receipt-v1'});normalCleanupSucceeded=$false;rawUiOutcome=$outcome;references=$finalRefs;journal=$finalJournal}
}}
 )
}
