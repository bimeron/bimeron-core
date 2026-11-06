# Narrow host deadline and guest-operation ownership helpers. Dot-source only.
Set-StrictMode -Version Latest
$script:StockSubmittedOperations=@()
$script:StockSessionClosure=$null
$script:StockNicReads=@{}
function Start-StockNicReadback {
 $ps=[PowerShell]::Create()
 $null=$ps.AddScript({
  $n=@(Get-VM -Id '<LAB_VM_ID>' | Get-VMNetworkAdapter)
  if($n.Count -ne 1 -or $n[0].Id -cne 'Microsoft:<LAB_VM_ID_UPPER>\<LAB_VM_NIC_ID>' -or $n[0].MacAddress -cne '<LAB_GUEST_MAC_HEX>'){throw 'HOLD: exact NIC identity'}
  $switchType='';if($n[0].Connected){$switch=Get-VMSwitch -Id $n[0].SwitchId -ErrorAction Stop;$switchType=[string]$switch.SwitchType}
  return @{SwitchType=$switchType;Id=[string]$n[0].Id;MacAddress=[string]$n[0].MacAddress;Connected=[bool]$n[0].Connected;SwitchId=[string]$n[0].SwitchId}
 }.ToString())
 return $ps
}
function Get-StockNic {
 $key=$script:Controller.phase
 if(!$script:StockNicReads.ContainsKey($key)){$script:StockNicReads[$key]=@()}
 $reads=$script:StockNicReads[$key]
 if($reads.Count -eq 0 -or $reads[-1].state -ceq 'Failed'){
  $read=@{ps=$null;handle=$null;state='Submitting';result=$null;error=$null}
  $script:StockNicReads[$key]+=,$read
  try{$read.ps=Start-StockNicReadback;$read.handle=$read.ps.BeginInvoke();$read.state='Pending'}catch{$read.state='Unknown';$read.error=$_;throw}
 }else{$read=$reads[-1]}
 if($read.state -ceq 'Unknown'){throw 'NIC readback submission unknown; original reader retained'}
 if($read.state -ceq 'Pending'){
  if(!$read.handle.IsCompleted){throw 'Original NIC readback pending'}
  try{
   $read.result=@($read.ps.EndInvoke($read.handle))
   if($read.ps.Streams.Error.Count -or $read.result.Count -ne 1){throw 'NIC reader failed'}
   $read.state='Completed'
  }catch{$read.state='Failed';$read.error=$_;throw}
 }
 return $read.result[0]
}
function Disconnect-StockNic {throw 'Use the retained controller owned NIC operation'}
function Start-StockGuestOperation($Session,[scriptblock]$Body,[object[]]$Arguments,[bool]$Mutation) {
 foreach($prior in $script:StockSubmittedOperations){
  if($prior.ContainsKey('kind') -and $prior.kind -ceq 'host-nic'){continue}
  if(!$prior.resolved -and ($prior.submission -cne 'Submitted' -or $prior.collection -cne 'Collected')){throw 'Original guest operation must be collected before another submission'}
 }
 # Retain intent before transport submission: a throwing submission is unknown.
 $op=@{job=$null;session=$Session;mutation=$Mutation;resolved=$false;submission='Submitting';collection='Uncollected';terminal=$null;result=$null;errors=@();submissionError=$null;collectionError=$null;postcondition='Unverified';publication='Unpublished'}
 $script:StockSubmittedOperations+=,$op
 try {
  $op.job=Invoke-Command -Session $Session -ScriptBlock $Body -ArgumentList $Arguments -AsJob -ErrorAction Stop
  if($null -eq $op.job){throw 'Transport returned no owned job'}
  $op.submission='Submitted'
 } catch {
  $op.submission='Unknown';$op.submissionError=$_
  throw
 }
 return $op
}
function Complete-StockGuestOperation($Operation,[int]$Seconds) {
 if($Seconds -lt 0 -or $Seconds -gt 210){throw 'Collection wait outside bounds'}
 if($Operation.submission -cne 'Submitted' -or $null -eq $Operation.job){throw 'HOLD: submission ownership unknown'}
 if($Operation.resolved -and $Operation.ContainsKey('reconciliation') -and $Operation.reconciliation.ContainsKey('verifiedResult')){return $Operation.reconciliation.verifiedResult}
 if($Operation.collection -ceq 'Collected'){
  if($Operation.terminal -cne 'Completed' -or $Operation.errors.Count){throw 'HOLD: cached terminal failure; concrete effects require reconciliation'}
  return $Operation.result
 }
 $clock=New-StockOperationWaitClock
 while($Operation.job.State -in @('Running','NotStarted','Blocked') -and $clock.Elapsed.TotalSeconds -lt $Seconds){Start-Sleep -Milliseconds 50}
 if($Operation.job.State -notin @('Completed','Failed','Stopped')){
  $Operation.collection='Pending'
  throw 'HOLD: original operation pending'
 }
 # Keep the original stream in the original job even if collection itself throws.
 # Cache terminal output/errors before any publication; never remove the job here.
 $receiveErrors=@()
 try {
  $result=@(Receive-Job -Job $Operation.job -Keep -ErrorAction SilentlyContinue -ErrorVariable receiveErrors)
  $childErrors=@($Operation.job.ChildJobs | ForEach-Object {$_.Error})
  $Operation.result=$result
  $Operation.errors=@($receiveErrors)+@($childErrors)
  $Operation.terminal=[string]$Operation.job.State
  $Operation.collection='Collected';$Operation.collectionError=$null
 } catch {
  $Operation.collection='CollectionUnknown';$Operation.collectionError=$_
  throw
 }
 if($Operation.terminal -cne 'Completed' -or $Operation.errors.Count){throw 'HOLD: terminal failure retained; concrete effects require reconciliation'}
 $Operation.resolved=$true
 return $Operation.result
}
function Wait-StockDeadline($ReadOperation,[Diagnostics.Stopwatch]$Clock,[scriptblock]$Isolate={Disconnect-StockNic}) {
 # Clock MUST already be running before asynchronous permit publication.
 if(!$Clock.IsRunning){throw 'Deadline clock not running'}
 while($Clock.Elapsed.TotalSeconds -lt 60 -and $ReadOperation.job.State -in @('Running','NotStarted','Blocked')){Start-Sleep -Milliseconds 25}
 # Host-local isolation precedes Receive-Job and every guest SCM mutation.
 $isolation=& $Isolate
 return $isolation
}
function Close-StockSession($Session,$Operations) {
 foreach($reads in $script:StockNicReads.Values){foreach($read in $reads){if($read.state -cnotin @('Completed','Failed')){throw 'Outstanding original NIC reader'}}}
 if(@(@($Operations)+@($script:StockSubmittedOperations) | Where-Object {!$_.resolved}).Count){throw 'HOLD: outstanding operation; session retained'}
 foreach($op in $script:StockSubmittedOperations){if($op.submission -cne 'Submitted' -or $op.collection -cne 'Collected' -or ($op.terminal -cne 'Completed' -and !$op.ContainsKey('reconciliation'))){throw 'Original terminal evidence/reconciliation missing'}}
 if($null -eq $script:StockSessionClosure){
  $script:StockSessionClosure=@{session=$Session;attempted=$true;returned=$false;error=$null}
  try{Remove-PSSession -Session $Session -ErrorAction Stop;$script:StockSessionClosure.returned=$true}catch{$script:StockSessionClosure.error=$_}
 }
 if(![object]::ReferenceEquals($Session,$script:StockSessionClosure.session)){throw 'Session closure owner changed'}
 if($Session.State -ne 'Closed'){throw 'HOLD: session closure unproven'}
 return @{state='Closed';outstandingReads=0;outstandingMutations=0}
}
function Invoke-StockOwnedNic($Controller,[ValidateSet('disconnect','reconnect')][string]$Direction,$OriginalNic) {
 $key='nic-'+$Direction
 if(!$Controller.operations.ContainsKey($key)){
  $op=@{kind='host-nic';submission='Intent';collection='Pending';resolved=$false;mutation=$true;terminal=$null;ps=$null;handle=$null;errors=@();result=$null;direction=$Direction;original=$OriginalNic}
  $Controller.operations[$key]=$op;$script:StockSubmittedOperations+=,$op
  try{$op.ps=Start-StockNicInvocation $Direction $OriginalNic;$op.handle=$op.ps.BeginInvoke();$op.submission='Submitted'}catch{$op.submission='Unknown';$op.errors+=,$_ ;throw}

 }
 $op=$Controller.operations[$key]
 if($op.submission -cne 'Submitted'){throw 'Host NIC submission unknown'}
 if($op.collection -cne 'Collected'){
  if(!$op.handle.IsCompleted){throw 'Original host NIC operation pending'}
  # EndInvoke is attempted exactly once; preserve errors even if it throws.
  $op.collection='Collecting'
  try{$op.result=@($op.ps.EndInvoke($op.handle));$op.terminal='Completed'}catch{$op.errors+=,$_;$op.terminal='Failed'}
  $op.errors+=@($op.ps.Streams.Error);$op.collection='Collected'
 }
 $n=Get-StockNic
 if($n.Id -cne $op.original.Id -or $n.MacAddress -cne $op.original.MacAddress){throw 'NIC reconciliation foreign identity'}
 if($Direction -ceq 'disconnect'){
  if($n.Connected -or ($n.SwitchId -and [guid]$n.SwitchId -ne [guid]::Empty)){throw 'Original disconnect effects unproven'}
 }elseif(!$n.Connected -or [string]$n.SwitchId -ine '<LAB_VSWITCH_ID>'){throw 'Original reconnect effects unproven'}
 $op.reconciliation=@{originalTerminal=$op.terminal;id=[string]$n.Id;mac=[string]$n.MacAddress;connected=[bool]$n.Connected;switchId=$(if($n.Connected){[string]$n.SwitchId}else{''})}
 $op.postcondition='VerifiedNicReadback';$op.postconditionEvidence=$op.reconciliation
 $op.resolved=$true
 return $op.reconciliation
}

function Start-StockNicInvocation($Direction,$OriginalNic) {
  $ps=[PowerShell]::Create()
  $body={param($direction,$vm,$id,$mac,$switchId)
   $n=@(Get-VM -Id $vm|Get-VMNetworkAdapter)
   if($n.Count -ne 1 -or $n[0].Id -cne $id -or $n[0].MacAddress -cne $mac){throw 'NIC mutation identity'}
   if($direction -ceq 'disconnect'){
    if(!$n[0].Connected -or [string]$n[0].SwitchId -ine $switchId){throw 'Disconnect starting topology'}
    Disconnect-VMNetworkAdapter -VMNetworkAdapter $n[0] -Confirm:$false -ErrorAction Stop
   }else{
    if($n[0].Connected -or ($n[0].SwitchId -and [guid]$n[0].SwitchId -ne [guid]::Empty)){throw 'Reconnect starting topology'}
    $switch=Get-VMSwitch -Id $switchId -ErrorAction Stop
    if([string]$switch.SwitchType -cne 'Private'){throw 'Private switch changed'}
    Connect-VMNetworkAdapter -VMNetworkAdapter $n[0] -VMSwitch $switch -Confirm:$false -ErrorAction Stop
   }
  }
  $null=$ps.AddScript($body.ToString()).AddArgument($Direction).AddArgument('<LAB_VM_ID>').AddArgument([string]$OriginalNic.Id).AddArgument([string]$OriginalNic.MacAddress).AddArgument('<LAB_VSWITCH_ID>')
  return $ps
}

function New-StockOperationWaitClock {return [Diagnostics.Stopwatch]::StartNew()}
