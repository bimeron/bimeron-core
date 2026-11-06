param([Parameter(Mandatory=$true)][string]$ProofPath,[Parameter(Mandatory=$true)][string]$ConfigPath,[Parameter(Mandatory=$true)][string]$PythonPath)
$ErrorActionPreference='Stop'
$script:StockMainStarted=$false
trap {
 if(!$script:StockMainStarted){
  # Diagnostic only: no release authority and no fabricated administrative receipt.
  @{schema='stock-pre-admission-failure-v1';deploymentAttempted=$false;permitSubmission='NeverInitiated';normalCleanupSucceeded=$false;error=[string]$_.Exception.Message}|ConvertTo-Json -Compress|Write-Output
 }
 break
}
. "$PSScriptRoot/../driver/protected-guest.ps1"
. "$PSScriptRoot/stock-host-operations.ps1"
. "$PSScriptRoot/stock-wire.ps1"
. "$PSScriptRoot/stock-guest.ps1"
. "$PSScriptRoot/stock-human.ps1"
. "$PSScriptRoot/stock-recovery.ps1"
. "$PSScriptRoot/stock-controller-phases.ps1"
$proof=Assert-StrictOwnerJson ([IO.File]::ReadAllBytes($ProofPath))
$binding=$proof.admission.Binding;$nonce=$binding.Nonce
Assert-OwnerFields $binding @('SHA256','Nonce','PolicySHA256')
foreach($h in @($binding.SHA256,$binding.Nonce,$binding.PolicySHA256)){if($h -isnot [string] -or $h -cnotmatch '^[a-f0-9]{64}$'){throw 'Binding digest'}}
$base=Split-Path -LiteralPath $ProofPath
# The private run root name comes from admission and is bound by its run-identity.json.
$privateRoot=Split-Path $base
$runIdentityPath=Join-Path $privateRoot 'run-identity.json'
if((Split-Path -Leaf $base) -cne 'live' -or ![IO.File]::Exists($runIdentityPath)){throw 'Operational evidence path'}
$runIdentity=Assert-StrictOwnerJson ([IO.File]::ReadAllBytes($runIdentityPath))
if($runIdentity.schema -cne 'fresh-admin-run-identity-v1' -or $runIdentity.nonce -cne $nonce -or $runIdentity.rootName -cne (Split-Path -Leaf $privateRoot)){throw 'Operational evidence path'}
if([IO.Path]::GetFullPath($ConfigPath) -ine [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../stock-control-config.json'))){throw 'Operational configuration path'}
# The admitted interpreter path from the owner; never a PATH/cwd lookup.
if(![IO.Path]::IsPathRooted($PythonPath) -or $PythonPath -notmatch '^[A-Za-z]:[\\/]' -or ![IO.File]::Exists($PythonPath)){throw 'Absolute interpreter path required'}
$script:StockPython=$PythonPath
$root=Join-Path $base 'stock'
if(Test-Path -LiteralPath $root){throw 'Stock control already attempted'}
$null=New-Item -ItemType Directory -Path $root
function Save-Stock([string]$Name,$Value) {
 $publicationName=$Name+'.json'
 if($script:Controller.publications.ContainsKey($publicationName)){$bytes=$script:Controller.publications[$publicationName].bytes}else{
  $Value=$Value.Clone();$Value.nonce=$nonce;$Value.binding=$binding
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 60 -Compress))
 }
 return Publish-StockCached $script:Controller ($Name+'.json') $bytes {
  param($name,$data)Write-StockEvidenceFile $script:Controller $root $name $data
 } {param($name)Read-StockEvidenceBytes (Join-Path $root $name)}
}
function Call-Stock([scriptblock]$Body,[object[]]$Arguments,[int]$Seconds,[bool]$Mutation=$false,[string]$OperationId='') {
 if(!$OperationId){$OperationId=$script:Controller.phase+'-'+(Get-StockHash ([Text.Encoding]::UTF8.GetBytes($Body.ToString()+($Arguments|ConvertTo-Json -Depth 60 -Compress))))}
 if(!$script:Controller.operations.ContainsKey($OperationId)){
  # Install an ownership placeholder before submission can throw.
  $script:Controller.operations[$OperationId]=@{submission='Unknown';resolved=$false}
  $op=Start-StockGuestOperation $session $Body $Arguments $Mutation
  $script:Controller.operations[$OperationId]=$op
 }
 $op=$script:Controller.operations[$OperationId]
 if($op.submission -cne 'Submitted'){throw 'Original operation submission unknown'}
 try{$value=Complete-StockGuestOperation $op $Seconds;$op.postcondition=$(if($op.terminal -ceq 'Failed'){'ReconciledPredicateOrPhase'}else{'VerifiedByOriginalBody'});$op.postconditionEvidence=$value;return $value}catch{
  if($op.collection -cne 'Collected' -or $op.terminal -cne 'Failed'){throw}
  if(!$Mutation -and $OperationId -cin @('no-permit-evidence','no-permit-restored','before-reconnect','after-reconnect','disposition-ownership')){
   return Complete-StockObservationRetry $script:Controller $session $OperationId $op $Body $Arguments $Seconds
  }
  if($Body.ToString() -cnotmatch 'Invoke-StockGuestPhase'){throw}
  if(!$op.ContainsKey('repairs')){$op.repairs=@()}
  if(!$op.ContainsKey('repair') -or ($op.repair.collection -ceq 'Collected' -and $op.repair.terminal -ceq 'Failed')){
   $op.repair=Start-StockGuestOperation $session {param($name)Repair-StockGuestPhase $name} $Arguments $false
   $op.repairs+=,$op.repair
  }
  $result=Complete-StockGuestOperation $op.repair $Seconds
  foreach($readback in $op.repairs){if(!$readback.resolved -and $readback.collection -ceq 'Collected' -and $readback.terminal -ceq 'Failed'){$readback.reconciliation=@{kind='subsequent-phase-readback';phase=$OperationId;verifiedResult=$result;originalFailed=$true};$readback.resolved=$true}}
  $op.reconciliation=@{phase=$OperationId;originalFailed=$true;verifiedResult=$result};$op.postcondition='Reconciled';$op.postconditionEvidence=$result;$op.resolved=$true
  return $result
 }
}
function Zero-Stock($State,$Baseline) {
 $bfe=@($Baseline.services|Where-Object name -CEQ 'BFE')[0];$bfea=@($State.services|Where-Object name -CEQ 'BFE')[0]
 $pa=@($Baseline.services|Where-Object name -CEQ 'PolicyAgent')[0];$paa=@($State.services|Where-Object name -CEQ 'PolicyAgent')[0]
 $b=@{state=$bfe.state;identity=(Get-StockIdentity $bfe)};$a=@{state=$bfea.state;identity=(Get-StockIdentity $bfea)}
 $p=@{state=$pa.state;identity=(Get-StockIdentity $pa)};$q=@{state=$paa.state;identity=(Get-StockIdentity $paa)}
 if(($b|ConvertTo-Json -Depth 8 -Compress) -cne ($a|ConvertTo-Json -Depth 8 -Compress) -or ($p|ConvertTo-Json -Depth 8 -Compress) -cne ($q|ConvertTo-Json -Depth 8 -Compress)){throw 'BFE/PolicyAgent baseline changed'}
 return @{ras=$State.ras;main=$State.main;quick=$State.quick;rasReaderSucceeded=$State.rasReaderSucceeded;saReaderSucceeded=$State.saReaderSucceeded;bfeBefore=$b;bfeAfter=$a;policyAgentBefore=$p;policyAgentAfter=$q}
}
$c=Assert-StrictOwnerJson ([IO.File]::ReadAllBytes($ConfigPath))
Assert-OwnerFields $c @('schema','nonce','launcherPath','launcherSHA256','reviewPath','reviewSHA256','phonebook','files')
if($c.schema -cne 'stock-control-config-v1' -or $c.nonce -cne $nonce){throw 'Stock configuration binding'}
foreach($pair in @(@('readback.json',$proof.admission.GuardSHA256),@('before.json',$proof.beforeSHA256),@('after.json',$proof.afterSHA256),@('guard.nft',$proof.rulesSHA256))){if((Get-StockHash ([IO.File]::ReadAllBytes((Join-Path $base $pair[0])))) -cne $pair[1]){throw 'Guard artifact changed'}}
if($proof.beforeSHA256 -cne $proof.afterSHA256){throw 'Guard baseline mismatch'}
$exe=[IO.File]::ReadAllBytes($c.launcherPath)
if((Get-StockHash $exe) -cne $c.launcherSHA256){throw 'Launcher digest'}
$reviewBytes=[IO.File]::ReadAllBytes($c.reviewPath)
if((Get-StockHash $reviewBytes) -cne $c.reviewSHA256){throw 'Review digest'}
$review=Assert-StrictOwnerJson $reviewBytes
Assert-OwnerFields $review @('schema','effort','verdict','launcherSHA256','files','administrativeQuiescenceAccepted')
if($review.schema -cne 'stock-review-v1' -or $review.effort -cne 'HIGH' -or $review.verdict -cne 'APPROVED' -or $review.launcherSHA256 -cne $c.launcherSHA256 -or $review.administrativeQuiescenceAccepted -isnot [bool] -or !$review.administrativeQuiescenceAccepted){throw 'Completed exact HIGH review missing'}
$required=@('stock-control.ps1','stock-host-operations.ps1','stock-service-operations.ps1','stock-wire.ps1','stock-guest.ps1','stock-human.ps1','StockProcessPin.cs','stock-check-protection.py','stock-recovery.ps1','stock-controller-phases.ps1')
Assert-OwnerFields $c.files $required
Assert-OwnerFields $review.files $required
foreach($name in $required){
 $hash=Get-StockHash ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name)))
 if($c.files.$name -cne $hash -or $review.files.$name -cne $hash){throw 'Reviewed controller bytes mismatch'}
}
Initialize-StockRecoveryDirectory $root
$candidate=$c.reviewSHA256
$script:Controller=New-StockControllerState $nonce $candidate (Get-StockControllerPhases)
$script:Controller.noPermit=$false
$null=Save-Stock 'recovery-endpoint' @{schema='stock-recovery-endpoint-v1';candidate=$candidate;verbs=@('inspect','reconcile','continue-disposition');authentication='protected-local-owner-acl'}
try{$ready=Wait-StockHuman $root $binding $proof.admission.GuardSHA256 $c.launcherSHA256 $c.reviewSHA256}catch{
 $null=Save-Stock 'human-rejected' @{reason=[string]$_.Exception.Message}
 $ready=$null
}
if($null -eq $ready){
 $null=Save-Stock 'precleanup' @{schema='stock-no-launch-v1';normalCleanupSucceeded=$false;reason='human-ready-unavailable';deploymentAttempted=$false;permitPublished=$false;serviceMutations=0;rawUiOutcome=@{state='unknown'}}
 exit 0
}
Assert-StockHumanCurrent $root $ready

$script:Controller.localNames=@('ProofPath','ack','admin','after','before','binding','bytes','c','c1','c1raw','closed','config','deadline','deployed','exe','expires','file','finalJournal','finalRefs','guestPhase','init','isolated','isolation','isolationAttempted','isolationRef','journal','key','late','lateIndex','ledger','n','name','nic','noPermitEvidence','nonce','nr','op','operations','originalNic','originalSwitch','outcome','permit','permitExpires','pin','pr','pre','preRef','proof','rawRef','read','ready','reconnectAttempted','refs','release','request','restored','restoredState','result','root','s','sample','session','sessionAttempted','source','sources','state','stopped','switch','taskClosure','timer')
foreach($localKey in $script:Controller.localNames){$v=Get-Variable -Name $localKey -ErrorAction SilentlyContinue;$script:Controller.locals[$localKey]=$(if($v){$v.Value}else{$null})}
$script:StockMainStarted=$true
while($script:Controller.status -cne 'Complete'){
 Invoke-StockControllerCycle $script:Controller
 if($script:Controller.status -ceq 'HOLD'){
  try{Read-StockRecoveryEndpoint $script:Controller $root}catch{$script:Controller.error=[string]$_.Exception.Message}
 }
 if($script:Controller.status -cin @('HOLD','WaitingForFinalization')){Start-Sleep -Milliseconds 100}
}
