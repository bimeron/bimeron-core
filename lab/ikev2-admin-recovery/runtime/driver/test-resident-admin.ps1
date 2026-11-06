$ErrorActionPreference='Stop'
. "$PSScriptRoot/resident-guest.ps1"
. "$PSScriptRoot/../host/stock-recovery.ps1"
function Need($Condition,[string]$Message){if(!$Condition){throw $Message}}
function Reject([scriptblock]$Body){$rejected=$false;try{& $Body|Out-Null}catch{$rejected=$true};Need $rejected 'Expected refusal'}
$script:calls=0;$script:collections=0;$script:closes=0;$script:reserved=0;$script:throwStart=$false
function Start-ResidentInvocation($State,$Request){
 Need ($script:reserved -gt 0) 'Invocation before reservation'
 $script:calls++
 if($script:throwStart){throw 'inert unknown submission'}
 $ps=[pscustomobject]@{Streams=[pscustomobject]@{Error=@()}}
 $ps|Add-Member ScriptMethod EndInvoke {param($Handle)$script:collections++;return 'original output'}
 $State.active.ps=$ps
 return [pscustomobject]@{IsCompleted=$false}
}
function Remove-PSSession {param($Session,$ErrorAction)$script:closes++;$Session.State='Closed'}
function Request($Sequence=1,$Operation='sample',$Mode='submit'){
 return @{schema='fresh-resident-request-v1';nonce=('a'*64);configSHA256=('b'*64);sequence=$Sequence;mode=$Mode;operation=$Operation;path='INERT';requestSHA256=('c'*64)}
}
$reserve={param($Id,$Raw)$script:reserved++}
$state=New-ResidentGuestState ('a'*64) ('b'*64)
$record=Submit-ResidentRequest $state (Request) $reserve
Need ($record.state -ceq 'Pending') 'Pending original missing'
$null=Collect-ResidentOriginal $state
Need ($script:collections -eq 0) 'Collected pending operation'
Reject {Close-ResidentOriginal $state $reserve}
Need ($script:closes -eq 0) 'Closed pending session'
$record.handle.IsCompleted=$true
$null=Collect-ResidentOriginal $state;$null=Collect-ResidentOriginal $state
Need ($script:collections -eq 1 -and $record.output[0] -ceq 'original output') 'Repeated/lost original collection'
$null=Submit-ResidentRequest $state (Request) $reserve
Need ($script:calls -eq 1) 'Duplicate request replay'
$state.session=[pscustomobject]@{State='Opened'};$state.sessionAttempted=$true
$receipt=Close-ResidentOriginal $state $reserve
$null=Close-ResidentOriginal $state $reserve
Need ($script:closes -eq 1 -and $receipt.sessionState -ceq 'Closed') 'Positive close failed'
foreach($operation in @('preflight','exit-supervisor')){
 $other=New-ResidentGuestState ('a'*64) ('b'*64)
 Reject {Submit-ResidentRequest $other (Request 1 $operation 'fetch') $reserve}
}
$state=New-ResidentGuestState ('a'*64) ('b'*64);$script:throwStart=$true
Reject {Submit-ResidentRequest $state (Request) $reserve}
$null=Submit-ResidentRequest $state (Request) $reserve
Reject {Submit-ResidentRequest $state (Request 2) $reserve}
Reject {Close-ResidentOriginal $state $reserve}
Need ($script:calls -eq 2) 'Unknown submission replay'
$state=New-ResidentGuestState ('a'*64) ('b'*64)
Reject {Submit-ResidentRequest $state (Request) {throw 'inert reservation flush'}}
Need ($script:calls -eq 2) 'Effect after reservation failure'
$script:throwStart=$false
$null=Submit-ResidentRequest $state (Request) $reserve
$null=Submit-ResidentRequest $state (Request) $reserve
Need ($script:calls -eq 3) 'Known pre-dispatch reservation recovery replayed invocation'
$state=New-ResidentGuestState ('a'*64) ('b'*64)
$state.session=[pscustomobject]@{State='Opened'};$state.sessionAttempted=$true
Reject {Close-ResidentOriginal $state {throw 'inert close reservation failure'}}
Need (!$state.closeAttempted) 'Close marked attempted before durable reservation'
$null=Close-ResidentOriginal $state $reserve
Need ($state.closed -and $script:closes -eq 2) 'Original close did not recover before first dispatch'

# Actual stock dispatcher with inert phase advancement, before/after reservation.
$script:StockNicReads=@{};$script:StockSubmittedOperations=@();$script:advanced=0
function Invoke-StockControllerCycle($State,[switch]$Continue){$script:advanced++;throw 'inert outcome publication loss'}
$state=New-StockControllerState ('a'*64) ('b'*64) @()
$q=@{schema='stock-recovery-request-v1';nonce=('a'*64);candidate=('b'*64);requestId=1;verb='continue-disposition'}
Reject {Invoke-StockRecoveryRequest $state $q $reserve}
Reject {Invoke-StockRecoveryRequest $state $q $reserve}
$q.requestId=2
Reject {Invoke-StockRecoveryRequest $state $q $reserve}
Need ($script:advanced -eq 1) 'Stock advancement replay'
$state=New-StockControllerState ('a'*64) ('b'*64) @();$q.requestId=1
$notDispatched=Invoke-StockRecoveryRequest $state $q {throw 'inert flush'}
Need ($script:advanced -eq 1 -and $notDispatched.dispatched -eq $false -and $state.requests[1L].state -ceq 'NotDispatched') 'Stock effect before durable reserve'
Need ([object]::ReferenceEquals((Invoke-StockRecoveryRequest $state $q $reserve),$notDispatched)) 'Not-dispatched response not cached'
$q.requestId=2
Reject {Invoke-StockRecoveryRequest $state $q $reserve}
Need ($script:advanced -eq 2 -and $state.requests[2L].state -ceq 'Reserved') 'Not-dispatched request blocked next explicit ID'
# Exercise the actual fixed policy/readback bodies with all operational commands
# replaced before entry. No session, service, VM, credential or policy API runs.
. "$PSScriptRoot/protected-guest.ps1"
function New-PSSession {throw 'Forbidden native session in inert test'}
function Import-Clixml {throw 'Forbidden credential input in inert test'}
$script:policy='Bypass';$script:policyWrites=0;$script:invokeMode='policy';$script:seenSession=$null
$global:BimeronOriginalProcessPolicy=@{nonce=('a'*64);value='Undefined';restored=$false}
function Get-ExecutionPolicy {param($Scope)if($Scope -ceq 'Process'){$script:policy}else{'Undefined'}}
function Set-ExecutionPolicy {param($Scope,$ExecutionPolicy,[switch]$Force)
 Need ($Scope -ceq 'Process' -and $global:BimeronOriginalProcessPolicy.restored) 'Policy effect before original reservation'
 $script:policyWrites++;$script:policy=$ExecutionPolicy
}
function Invoke-Command {param($Session,$ArgumentList,$ScriptBlock)
 $script:seenSession=$Session
 if($script:invokeMode -ceq 'policy'){
  Need ([string]$ArgumentList -ceq ('a'*64)) ('Inert policy argument mismatch: '+[string]$ArgumentList)
  & $ScriptBlock ([string]$ArgumentList)
 }else{@{BFE='Running';RasMan='Running';IKEEXT='Stopped';PolicyAgent='Stopped'}}
}
$scratch=Join-Path $PSScriptRoot ('../../test-temporary/resident-body-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $scratch
$path=Join-Path $scratch 'context.json';[IO.File]::WriteAllText($path,'{}')
$state=New-ResidentGuestState ('a'*64) ('b'*64)
$state.session=[pscustomobject]@{State='Opened'};$state.sessionAttempted=$true;$state.sessionValidated=$true
$q=@{path=$path;requestSHA256=(Get-OwnerSHA256 ([IO.File]::ReadAllBytes($path)));operation='restore-session-policy';mode='submit'}
$result=Invoke-ResidentGuestBody $state $q|ConvertFrom-Json
Need ($result.restored -and $result.value -ceq 'Undefined' -and $script:policyWrites -eq 1) 'Original Process policy not restored'
Reject {Invoke-ResidentGuestBody $state $q}
Need ($script:policyWrites -eq 1) 'Policy restoration replayed'
$script:invokeMode='readback';$q.operation='services'
$result=Invoke-ResidentGuestBody $state $q|ConvertFrom-Json
Need ([object]::ReferenceEquals($script:seenSession,$state.session) -and $result.BFE -ceq 'Running') 'Readback replaced original session'
# Live regression: seal-no-launch ({} body) through the actual resident body,
# Submit-OwnerCommand and Fetch-OwnerResponse under the resident's strict mode.
# Invoke-Command is replaced; no session, guest or VM is reachable.
$script:invokeMode='owner';$script:ownerCalls=@()
function Invoke-Command {param($Session,$ArgumentList,$ScriptBlock)
 if($script:invokeMode -ceq 'owner'){$script:ownerCalls+=,@($ArgumentList);if($script:ownerCalls.Count -eq 2){return $script:ownerBundle};return}
 throw 'Unexpected inert Invoke-Command'
}
$ot=Join-Path ([IO.Path]::GetFullPath($scratch)) 'owner-transport'
foreach($d in 'commands','responses','proofs','samples'){$null=New-Item -ItemType Directory -Path (Join-Path $ot $d)}
[IO.File]::WriteAllText((Join-Path $ot 'config.json'),'{"inert":true}');$cfgHash=Get-OwnerSHA256 ([IO.File]::ReadAllBytes((Join-Path $ot 'config.json')))
$sealPath=Join-Path $ot 'commands/00000001.json'
[IO.File]::WriteAllText($sealPath,'{"schema":"full300-owner-command-v1","nonce":"'+('a'*64)+'","configSHA256":"'+$cfgHash+'","seq":1,"op":"seal-no-launch","body":{}}')
$sealHash=Get-OwnerSHA256 ([IO.File]::ReadAllBytes($sealPath))
$responseText='{"nonce":"'+('a'*64)+'","configSHA256":"'+$cfgHash+'","seq":1,"commandSHA256":"'+$sealHash+'","refs":[]}'
$script:ownerBundle=@{bytes=[Text.UTF8Encoding]::new($false).GetBytes($responseText);files=@()}
$q=@{path=$sealPath;requestSHA256=$sealHash;operation='seal-no-launch';mode='submit'}
$result=Invoke-ResidentGuestBody $state $q
Need ($result -ceq $responseText -and $script:ownerCalls.Count -eq 2 -and @($script:ownerCalls[0][2]).Count -eq 0) 'Seal-no-launch did not reach the original owner mailbox'
Need ([IO.File]::ReadAllText((Join-Path $ot 'responses/00000001.json')) -ceq $responseText) 'Seal-no-launch response not archived'
# exit-supervisor noLaunch body resolves its reference without strict-mode refusal.
[IO.File]::WriteAllText((Join-Path $ot 'proofs/no-launch.json'),'{}');$proof=[IO.File]::ReadAllBytes((Join-Path $ot 'proofs/no-launch.json'))
$exitRaw=[Text.Encoding]::UTF8.GetBytes('{"schema":"full300-owner-command-v1","nonce":"'+('a'*64)+'","configSHA256":"'+$cfgHash+'","seq":2,"op":"exit-supervisor","body":{"noLaunch":{"name":"no-launch.json","sha256":"'+(Get-OwnerSHA256 $proof)+'","length":'+$proof.Length+'}}}')
$exit=Assert-OwnerEnvelope $exitRaw ('a'*64) $cfgHash 2
Need (@(Get-OwnerTransitiveProofs $exit.body $ot $ot).Count -eq 1) 'Exit-supervisor noLaunch proof closure'
Reject {Assert-OwnerEnvelope ([Text.Encoding]::UTF8.GetBytes('{"schema":"full300-owner-command-v1","nonce":"'+('a'*64)+'","configSHA256":"'+$cfgHash+'","seq":3,"op":"exit-supervisor","body":{}}')) ('a'*64) $cfgHash 3}
# Failed original invocations carry bounded, single-line diagnostic text.
$failing=[pscustomobject]@{Streams=[pscustomobject]@{Error=@()}}
$failing|Add-Member ScriptMethod EndInvoke {param($Handle)throw ("inert failure`r`nline two "+('z'*900))}
$state=New-ResidentGuestState ('a'*64) ('b'*64)
$record=@{fingerprint='f';request=(Request);state='Pending';ps=$failing;handle=[pscustomobject]@{IsCompleted=$true};output=$null;errors=@();error=$null;collectAttempted=$false}
$state.active=$record
$null=Collect-ResidentOriginal $state
Need ($record.state -ceq 'Failed' -and $record.error -is [string] -and $record.error.Contains('inert failure') -and !$record.error.Contains("`n") -and $record.error.Length -le 512) ('Failed diagnostic missing: '+$record.error)
'PASS resident ownership, seal-no-launch strict-mode mailbox path, failure diagnostics, late collection, closure, policy/readback, no replay and stock reservation; operational boundaries inert'
