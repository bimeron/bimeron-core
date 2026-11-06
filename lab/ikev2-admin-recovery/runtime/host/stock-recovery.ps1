# Retained controller recovery; loaded by stock-control.ps1, never a standalone owner.
function New-StockControllerState([string]$Nonce,[string]$Candidate,$Phases) {
 return @{abortAdmission=$false;noPermit=$false;locals=@{};localNames=@();nonce=$Nonce;candidate=$Candidate;phases=$Phases;index=0;phase='initial';status='Running';error=$null;failures=@();requests=@{};lastRequest=0L;operations=@{};publications=@{};permitSubmission='NeverInitiated';captureRetained=$true;normalCleanupSucceeded=$false}
}
function Invoke-StockControllerTick($ControllerState) {
 if($ControllerState.index -ge $ControllerState.phases.Count){$ControllerState.status='Complete';return}
 $phaseEntry=$ControllerState.phases[$ControllerState.index];$ControllerState.phase=$phaseEntry.name
 foreach($localKey in $ControllerState.locals.Keys){Set-Variable -Name $localKey -Value $ControllerState.locals[$localKey] -Scope Local}
 try {
  Publish-StockFailureEvents $ControllerState
  . $phaseEntry.body
  if($ControllerState.status -ceq 'WaitingForFinalization'){return}
  $ControllerState.index++;$ControllerState.error=$null
  $ControllerState.status=$(if($ControllerState.index -eq $ControllerState.phases.Count){'Complete'}else{'Running'})
 } catch {
  $ControllerState.error=[string]$_.Exception.Message;$ControllerState.failures+=,@{phase=$ControllerState.phase;error=$ControllerState.error}
  $ControllerState.status='HOLD'
 } finally {
  foreach($localKey in $ControllerState.localNames){
   $localValue=Get-Variable -Name $localKey -Scope Local -ErrorAction SilentlyContinue
   if($null -ne $localValue){$ControllerState.locals[$localKey]=$localValue.Value}
  }
 }
}
function Get-StockControllerStatus($State) {
 return @{schema='stock-recovery-response-v1';nonce=$State.nonce;candidate=$State.candidate;phase=$State.phase;status=$State.status;unmetPrerequisite=$State.error;normalCleanupSucceeded=$false;captureRetained=$State.captureRetained;outstandingNicReaders=@($script:StockNicReads.Keys|ForEach-Object {$readKey=$_;foreach($reader in $script:StockNicReads[$readKey]){if($reader.state -cnotin @('Completed','Failed')){@{phase=$readKey;state=$reader.state}}}});outstanding=@($script:StockSubmittedOperations|Where-Object {!$_.resolved}|ForEach-Object {@{submission=$_.submission;collection=$_.collection;terminal=$_.terminal;mutation=$_.mutation}})}
}
function Invoke-StockRecoveryRequest($State,$Request,[scriptblock]$Reserve) {
 $expected=@('schema','nonce','candidate','requestId','verb')
 $keys=$(if($Request -is [hashtable]){@($Request.Keys)}elseif($Request -is [pscustomobject]){@($Request.PSObject.Properties|ForEach-Object {$_.Name})}else{throw 'Recovery request object'})
 if(@($keys|Where-Object {$_ -cnotin $expected}).Count -or @($keys).Count -ne $expected.Count){throw 'Recovery request fields'}
 if($Request.schema -cne 'stock-recovery-request-v1' -or $Request.nonce -cne $State.nonce -or $Request.candidate -cne $State.candidate){throw 'Recovery owner binding'}
 if($Request.verb -cnotin @('inspect','reconcile','continue-disposition')){throw 'Recovery verb forbidden'}
 if($Request.requestId -isnot [long] -and $Request.requestId -isnot [int]){throw 'Recovery request ID type'}
 $id=[long]$Request.requestId
 $fingerprint=$Request.verb
 if($State.requests.ContainsKey($id)){
  if($State.requests[$id].verb -cne $fingerprint){throw 'Recovery request ID reused with different body'}
  if($State.requests[$id].state -cnotin @('Complete','NotDispatched')){throw 'Original recovery request unresolved; no replay'}
  return $State.requests[$id].response
 }
 if($id -le $State.lastRequest){throw 'Recovery request ID not increasing'}
 if($Request.verb -cne 'inspect' -and @($State.requests.Values|Where-Object {$_.state -cnotin @('Complete','NotDispatched')}).Count){throw 'Original recovery request unresolved'}
 if($null -eq $Reserve){throw 'Durable reservation callback required'}
 $State.lastRequest=$id
 # Reserve in the original owner BEFORE any controller advancement or status
 # callback. Failure cannot leave a reusable request ID. Endpoint persistence
 # must have completed before entering this dispatcher.
 $State.requests[$id]=@{verb=$fingerprint;state='Reserved';response=$null}
 try{& $Reserve $id $Request}catch{
  # Known no-dispatch: cache under this ID, release it, never advance or replay.
  $State.requests[$id].response=@{schema='stock-recovery-response-v1';nonce=$State.nonce;candidate=$State.candidate;requestId=$id;dispatched=$false;reservation='failed';error=[string]$_.Exception.Message;normalCleanupSucceeded=$false}
  $State.requests[$id].state='NotDispatched'
  return $State.requests[$id].response
 }
 # The fixed current phase alone can advance; no request supplies executable code.
 if($Request.verb -cne 'inspect' -and $State.status -cne 'Complete'){Invoke-StockControllerCycle $State -Continue}
 $response=Get-StockControllerStatus $State;$response.requestId=$id
 $State.requests[$id].response=$response
 $State.requests[$id].state='Complete'
 return $response
}
function Publish-StockCached($State,[string]$Name,[byte[]]$Bytes,[scriptblock]$Write,[scriptblock]$Read) {
 if(!$State.publications.ContainsKey($Name)){$State.publications[$Name]=@{bytes=$Bytes.Clone();verified=$false}}
 $publication=$State.publications[$Name]
 if((Get-StockHash $Bytes) -cne (Get-StockHash $publication.bytes)){throw 'Immutable publication content changed'}
 if(!$publication.verified){
  # The writer must use CreateNew or compare the existing exact bytes.
  & $Write $Name $publication.bytes
  $actual=& $Read $Name
  if((Get-StockHash $actual) -cne (Get-StockHash $publication.bytes)){throw 'Publication readback mismatch'}
  $publication.verified=$true
 }
 return @{name=$Name;sha256=(Get-StockHash $publication.bytes);length=$publication.bytes.Length}
}
function Assert-StockRecoveryDirectory([string]$Directory) {
 Assert-StockAncestors $Directory
 $acl=Get-Acl -LiteralPath $Directory
 if(!$acl.AreAccessRulesProtected){throw 'Recovery directory inherited ACL'}
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -cnotin @($sid,'S-1-5-18','S-1-5-32-544')){throw 'Recovery directory foreign principal'}
 }
}
function Initialize-StockRecoveryDirectory([string]$Directory) {
 Assert-StockAncestors $Directory
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $acl=[Security.AccessControl.DirectorySecurity]::new()
 $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;'+$sid+')')
 Set-Acl -LiteralPath $Directory -AclObject $acl
 Assert-StockRecoveryDirectory $Directory
}
function Read-StockRecoveryEndpoint($State,[string]$Directory) {
 Assert-StockRecoveryDirectory $Directory
 $paths=@(Get-ChildItem -LiteralPath $Directory -Filter 'recovery-request-*.json'|Sort-Object Name)
 foreach($path in $paths){
  if($path.Name -cnotmatch '^recovery-request-[0-9]{20}\.json$' -or $path.Length -gt 4096){throw 'Recovery request bounds'}
  Assert-StockAncestors $path.FullName
  $request=Assert-StrictOwnerJson ([IO.File]::ReadAllBytes($path.FullName))
  if($path.Name -cne ('recovery-request-{0:D20}.json' -f [long]$request.requestId)){throw 'Recovery request filename binding'}
  $response=Invoke-StockRecoveryRequest $State $request {
   param($id,$value)
   $name='recovery-reserved-{0:D20}.json' -f $id
   $raw=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 10 -Compress))
   $null=Publish-StockCached $State $name $raw {param($n,$b)Write-StockEvidenceFile $State $Directory $n $b} {param($n)[IO.File]::ReadAllBytes((Join-Path $Directory $n))}
  }
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($response|ConvertTo-Json -Depth 30 -Compress))
  $name='recovery-response-{0:D20}.json' -f [long]$request.requestId
  $null=Publish-StockCached $State $name $bytes {param($n,$b)Write-StockEvidenceFile $State $Directory $n $b} {param($n)[IO.File]::ReadAllBytes((Join-Path $Directory $n))}
 }
}
function Assert-StockNoPermitLedger($State) {
 if($State.permitSubmission -cne 'NeverInitiated'){throw 'No-permit branch excluded by permit submission'}
 foreach($key in @('task-registration','task-start')){
  if(!$State.operations.ContainsKey($key)){throw 'Original deployment operation missing'}
  $op=$State.operations[$key]
  if($op.submission -cne 'Submitted' -or $op.collection -cne 'Collected' -or !$op.resolved){throw 'Original deployment operation unresolved'}
 }
 foreach($op in $script:StockSubmittedOperations){if(!$op.resolved){throw 'Original operation unresolved before no-permit settlement'}}
 $evidence=@{}
 foreach($key in @('task-registration','task-start')){
  $op=$State.operations[$key]
  $value=$(if($op.ContainsKey('reconciliation')){$op.reconciliation.verifiedResult}else{$op.result})
  if(@($value).Count -ne 1){throw 'Deployment original result shape'}
  $evidence[$key]=@{submission=$op.submission;collection=$op.collection;terminal=$op.terminal;result=@($value)[0];reconciled=$op.ContainsKey('reconciliation')}
 }
 return @{permitSubmission='NeverInitiated';originalDeploymentCollected=$true;originalOperationsReconciled=$true;operations=$evidence}
}

function Assert-StockContinuingProtection([string]$ProofPath) {
 & $script:StockPython "$PSScriptRoot/stock-check-protection.py" $ProofPath recovery
 if($LASTEXITCODE -ne 0){throw 'Continuing observer/capture protection failed'}
}
function Get-StockOperationEvidence($State) {
 $items=@();$index=0
 foreach($op in $script:StockSubmittedOperations){
  $names=@($State.operations.Keys|Where-Object {[object]::ReferenceEquals($State.operations[$_],$op)})
  $items+=,@{ordinal=$index;names=$names;submission=$op.submission;collection=$op.collection;terminal=$op.terminal;mutation=$op.mutation;resolved=$op.resolved;postcondition=$(if($op.ContainsKey('postcondition')){$op.postcondition}else{'RecordedInReconciliation'});publication=$(if($op.ContainsKey('publication')){$op.publication}else{'Unpublished'});result=$(if($op.ContainsKey('result')){$op.result}else{$null});errors=$(if($op.ContainsKey('errors')){@($op.errors|ForEach-Object {[string]$_})}else{@()});reconciliation=$(if($op.ContainsKey('reconciliation')){$op.reconciliation}else{$null})}
  $index++
 }
 return @{nicReaders=@($script:StockNicReads.Keys|ForEach-Object {$readKey=$_;foreach($reader in $script:StockNicReads[$readKey]){@{phase=$readKey;state=$reader.state;result=$reader.result;error=[string]$reader.error}}});permitSubmission=$State.permitSubmission;operations=$items;controllerFailures=$State.failures;normalCleanupSucceeded=$false}
}
function Write-StockPublicationBytes($Stream,[byte[]]$Bytes) {
 $Stream.Position=0;$Stream.SetLength(0);$Stream.Write($Bytes,0,$Bytes.Length);$Stream.Flush($true)
}
function Write-StockEvidenceFile($State,[string]$Directory,[string]$Name,[byte[]]$Bytes) {
 $publication=$State.publications[$Name];$path=Join-Path $Directory $Name
 if(Test-Path -LiteralPath $path){
  if((Get-StockHash ([IO.File]::ReadAllBytes($path))) -cne (Get-StockHash $Bytes)){throw 'Immutable evidence conflict'}
  return
 }
 if(!$publication.ContainsKey('file')){
  $publication.file=@{path=($path+'.pending');stream=$null;opened=$false;closed=$false}
  try{$publication.file.stream=[IO.File]::Open($publication.file.path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$publication.file.opened=$true}catch{throw}
 }
 $file=$publication.file
 if(!$file.opened){throw 'Publication temporary-file ownership unknown'}
 if(!$file.closed){
  Write-StockPublicationBytes $file.stream $Bytes
  $file.stream.Position=0;$check=New-Object byte[] $Bytes.Length
  if($file.stream.Read($check,0,$check.Length) -ne $check.Length -or (Get-StockHash $check) -cne (Get-StockHash $Bytes)){throw 'Owned publication write/readback mismatch'}
  $file.stream.Dispose();$file.closed=$true
 }
 # Rename only the same owned, flushed content; final names are never overwritten.
 [IO.File]::Move($file.path,$path)
}

function Invoke-StockControllerCycle($State,[switch]$Continue) {
 # This is the actual main-loop transition, shared by the mailbox and inert tests.
 if($State.abortAdmission -and $State.index -ge 15 -and $State.index -le 28){$State.index=29}
 $wake=($State.status -ceq 'WaitingForFinalization')
 if($State.status -ceq 'HOLD' -and $State.index -eq 63){$wake=Test-Path -LiteralPath (Join-Path $State.locals.root 'finalize-request.json')}
 if($State.status -ceq 'Running' -or $Continue -or $wake){
  $State.status='Running'
  Invoke-StockControllerTick $State
 }
 if($State.status -ceq 'HOLD' -and $State.index -ge 13 -and $State.index -le 28){
  if($State.permitSubmission -ceq 'NeverInitiated'){$State.abortAdmission=$true}
  if($State.index -ge 15){$State.index=29}
 }
}
function Publish-StockFailureEvents($State) {
 # Each failure has its own publication identity; existing journals never change.
 for($i=0;$i -lt $State.failures.Count;$i++){
  $name='controller-failure-{0:D6}' -f ($i+1)
  $null=Save-Stock $name @{schema='stock-controller-failure-v1';sequence=($i+1);failure=$State.failures[$i];normalCleanupSucceeded=$false}
 }
}
function Complete-StockObservationRetry($State,$Session,[string]$Id,$Original,[scriptblock]$Body,$Arguments,[int]$Seconds) {
 if($Original.mutation -or $Original.collection -cne 'Collected' -or $Original.terminal -cne 'Failed'){throw 'Original read not terminal/collected'}
 if(!$Original.ContainsKey('observations')){$Original.observations=@()}
 $last=$(if($Original.observations.Count){$Original.observations[-1]}else{$null})
 if($null -eq $last -or ($last.collection -ceq 'Collected' -and $last.terminal -ceq 'Failed')){
  $readId=$Id+'-observation-'+($Original.observations.Count+1)
  $placeholder=@{submission='Unknown';collection='Uncollected';terminal=$null;resolved=$false;mutation=$false}
  $Original.observations+=,$placeholder;$State.operations[$readId]=$placeholder
  $last=Start-StockGuestOperation $Session $Body $Arguments $false
  $Original.observations[$Original.observations.Count-1]=$last;$State.operations[$readId]=$last
  $last.observationId=$readId
 }
 if($last.submission -cne 'Submitted'){throw 'Replacement observation submission unknown'}
 $value=Complete-StockGuestOperation $last $Seconds
 $evidence=@{kind='same-predicate-observation';predicate=$Id;observationId=$last.observationId;verifiedResult=$value;originalFailed=$true}
 foreach($failed in @($Original)+@($Original.observations)){
  if($failed.collection -ceq 'Collected' -and $failed.terminal -ceq 'Failed'){$failed.reconciliation=$evidence;$failed.postcondition='ReconciledPredicate';$failed.resolved=$true}
 }
 return $value
}
function Select-StockDispositionBranch($State,$Ownership) {
 if($State.permitSubmission -cne 'NeverInitiated'){$State.noPermit=$false;return}
 if($Ownership.state -ceq 'NeverInitiated'){$State.noPermit=$true;return}
 if($Ownership.state -cne 'OwnedVerified' -or !$State.operations.ContainsKey('pin')){throw 'Original pin ownership unproven'}
 $pinOp=$State.operations['pin']
 if($pinOp.submission -cne 'Submitted' -or $pinOp.collection -cne 'Collected' -or $pinOp.terminal -cne 'Completed' -or !$pinOp.resolved){throw 'Original pin success not collected'}
 $pinResult=@($pinOp.result)[0]
 foreach($k in @('pid','creationFileTime','path','sha256')){if($pinResult.identity[$k] -cne $Ownership.identity[$k]){throw 'Original pin identity mismatch'}}
 $State.noPermit=$false
}

function Read-StockEvidenceBytes([string]$Path) {return [IO.File]::ReadAllBytes($Path)}
function Complete-StockPendingPublications($State,[string]$Directory) {
 # A pre-permit abort can leave a publication behind the new disposition phase.
 # Settle only already-intended bytes; this never submits a guest mutation.
 foreach($name in @($State.publications.Keys)){
  $publication=$State.publications[$name]
  if(!$publication.verified){
   $null=Publish-StockCached $State $name $publication.bytes {param($n,$b)Write-StockEvidenceFile $State $Directory $n $b} {param($n)Read-StockEvidenceBytes (Join-Path $Directory $n)}
  }
 }
}
