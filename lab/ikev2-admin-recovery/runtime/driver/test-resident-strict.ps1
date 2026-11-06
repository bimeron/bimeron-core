# Hermetic strict-mode coverage of every resident-reachable operation.
# The real Submit/Start/Collect/Close/Response functions run unchanged; the
# worker runspace dot-sources the real protected-guest.ps1 and resident-guest.ps1
# (Set-StrictMode -Version Latest). Only Invoke-Command, New-PSSession,
# Remove-PSSession and Import-Clixml are replaced inside that runspace, so no
# session, credential, guest or VM is reachable. Open-OwnerSession still takes
# the shared local session-start mutex for at most 3 seconds.
$ErrorActionPreference='Stop'
. "$PSScriptRoot/resident-guest.ps1"
. "$PSScriptRoot/owner-mailbox.ps1"
Set-StrictMode -Version Latest
function Need($Condition,[string]$Message){if(!$Condition){throw $Message}}
$nonce='a'*64;$configHash='b'*64
$scratch=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot ('../../test-temporary/resident-strict-'+[guid]::NewGuid().ToString('N'))))
$null=New-Item -ItemType Directory -Path $scratch
$utf8=[Text.UTF8Encoding]::new($false)
function Bytes([string]$Text){return ,$utf8.GetBytes($Text)}
function Write-Text([string]$Path,[string]$Text){[IO.File]::WriteAllBytes($Path,(Bytes $Text))}
$stubs={
 function global:Invoke-Command {param($Session,$ArgumentList,$ScriptBlock)
  $null=$StubPlan.calls.Add(@{session=$Session;args=@($ArgumentList)})
  if($StubPlan.queue.Count -eq 0){throw 'Unexpected inert Invoke-Command'}
  $next=$StubPlan.queue[0];$StubPlan.queue.RemoveAt(0)
  if($next.ContainsKey('throw')){throw $next.throw}
  if($next.ContainsKey('none')){return}
  if($next.ContainsKey('many')){foreach($item in $next.many){Write-Output $item};return}
  # One remote object, arrays unenumerated (Write-Output -NoEnumerate differs in PS7).
  if($next.value -is [array]){return ,$next.value};return $next.value
 }
 function global:New-PSSession {param($VMId,$Credential)$StubPlan.sessions++;return [pscustomobject]@{State='Opened';InstanceId=[guid]::NewGuid()}}
 function global:Remove-PSSession {param($Session,$ErrorAction)$Session.State='Closed'}
 function global:Import-Clixml {param($Path)return 'inert-credential'}
}.ToString()
function New-Case([object[]]$Queue,[switch]$Unvalidated){
 $state=New-ResidentGuestState $nonce $configHash
 $plan=[hashtable]::Synchronized(@{queue=[Collections.ArrayList]::Synchronized([Collections.ArrayList]::new());calls=[Collections.ArrayList]::Synchronized([Collections.ArrayList]::new());sessions=0})
 foreach($item in $Queue){$null=$plan.queue.Add($item)}
 $rs=[RunspaceFactory]::CreateRunspace();$rs.Open();$rs.SessionStateProxy.SetVariable('StubPlan',$plan)
 $ps=[PowerShell]::Create();$ps.Runspace=$rs;$null=$ps.AddScript($stubs).Invoke()
 Need (!$ps.HadErrors) 'Stub installation failed';$ps.Dispose()
 $state.runspace=$rs
 if(!$Unvalidated){$state.session=[pscustomobject]@{State='Opened'};$state.sessionAttempted=$true;$state.sessionValidated=$true}
 return @{state=$state;plan=$plan}
}
$script:sequence=0
function Invoke-Case($Case,[string]$Operation,[string]$Path,[string]$Mode='submit'){
 $state=$Case.state;$id=[long]($state.sequence+1)
 $request=@{schema='fresh-resident-request-v1';nonce=$nonce;configSHA256=$configHash;sequence=$id;mode=$Mode;operation=$Operation;path=$Path;requestSHA256=(Get-OwnerSHA256 ([IO.File]::ReadAllBytes($Path)))}
 $record=Submit-ResidentRequest $state $request {param($i,$raw)}
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while(!$record.handle.IsCompleted){if($watch.Elapsed.TotalSeconds -gt 60){throw 'Inert invocation did not complete'};Start-Sleep -Milliseconds 20}
 $null=Collect-ResidentOriginal $state
 $response=Get-ResidentResponse $state $record
 # The published form must serialize exactly as resident-main publishes it.
 $null=$response|ConvertTo-Json -Depth 20 -Compress
 return $response
}
function Output($Response){return $utf8.GetString([Convert]::FromBase64String($Response.output))}
function Collected($Response,[string]$Label){Need ($Response.state -ceq 'Collected' -and $null -eq $Response.error) ($Label+': '+$Response.state+' '+$Response.error);return (Output $Response)}
function Failed($Response,[string]$Label,[string]$Contains){Need ($Response.state -ceq 'Failed' -and $null -eq $Response.output -and $Response.error -is [string] -and $Response.error.Contains($Contains)) ($Label+': '+$Response.state+' '+$Response.error)}
$count=0
$context=Join-Path $scratch 'context.json';Write-Text $context '{}'

# Session admission and original Process policy capture (retained variant).
$case=New-Case @(@{value='<LAB_GUEST_NAME>'},@{value='S-1-5-21-inert'}) -Unvalidated
$text=Collected (Invoke-Case $case 'principal' $context) 'principal after admission'
Need ($text -ceq 'S-1-5-21-inert' -and $case.plan.sessions -eq 1 -and $case.state.sessionValidated) 'Session admission'
$first=$case.plan.calls[0].args
Need ($first.Count -eq 2 -and $first[0] -ceq $nonce -and $first[1] -eq $true) 'Policy capture must be retained'
$count++
$case=New-Case @(@{value='WRONG-GUEST'}) -Unvalidated
Failed (Invoke-Case $case 'principal' $context) 'wrong guest identity' 'Guest identity mismatch'
Need ($case.state.sessionAttempted -and !$case.state.sessionValidated -and $null -ne $case.state.session) 'Unvalidated session not retained'
$count++
$case=New-Case @(@{none=$true}) -Unvalidated
Failed (Invoke-Case $case 'principal' $context) 'empty admission output' 'Guest identity mismatch';$count++

# Output shapes: $null, empty, many and non-string results become Failed.
foreach($shape in @(@{value=$null},@{none=$true},@{many=@('a','b')},@{value=@{a=1}},@{value=@('single')})){
 $case=New-Case @($shape)
 Failed (Invoke-Case $case 'principal' $context) 'principal shape' 'Resident output shape';$count++
}

# Process policy restoration result is returned verbatim.
$case=New-Case @(@{value='{"nonce":"'+$nonce+'","scope":"Process","value":"Undefined","restored":true}'})
$null=Collected (Invoke-Case $case 'restore-session-policy' $context) 'restore-session-policy';$count++
$case=New-Case @(@{none=$true})
Failed (Invoke-Case $case 'restore-session-policy' $context) 'restore-session-policy empty' 'Resident output shape';$count++
$case=New-Case @(@{throw='Original policy restoration binding'})
Failed (Invoke-Case $case 'restore-session-policy' $context) 'restore-session-policy remote refusal' 'Original policy restoration binding';$count++

# Administrative readbacks.
$case=New-Case @(@{value=@{BFE='Running';RasMan='Running';IKEEXT='Stopped';PolicyAgent='Stopped'}})
$services=Collected (Invoke-Case $case 'services' $context) 'services'|ConvertFrom-Json
Need ($services.IKEEXT -ceq 'Stopped') 'Services value';$count++
foreach($bad in @(@{value=@{BFE='Running';RasMan='Running';IKEEXT='Stopped'}},@{value=$null},@{none=$true},@{value=@{BFE='Running';RasMan='Running';IKEEXT='Stopped';PolicyAgent=$null}})){
 $case=New-Case @($bad)
 Failed (Invoke-Case $case 'services' $context) 'services incomplete' 'Service readback';$count++
}
foreach($operation in @('guest','absence')){
 $case=New-Case @(@{value=@{guest='<LAB_GUEST_NAME>';owners=@();shells=@(@{pid=1});task=@{state=3;instances=0}}})
 $value=Collected (Invoke-Case $case $operation $context) $operation|ConvertFrom-Json
 Need (@($value.shells).Count -eq 1) ($operation+' single-element array');$count++
 foreach($empty in @(@{value=$null},@{none=$true})){
  $case=New-Case @($empty)
  Failed (Invoke-Case $case $operation $context) ($operation+' empty') 'Administrative readback produced no value';$count++
 }
}

# guest-read.ps1 resident modes through the retained session.
foreach($operation in @('clock','ready','integration')){
 $case=New-Case @(@{value='{"inert":"'+$operation+'"}'})
 Need ((Collected (Invoke-Case $case $operation $context) $operation) -ceq ('{"inert":"'+$operation+'"}')) ($operation+' value');$count++
 $case=New-Case @(@{none=$true})
 Failed (Invoke-Case $case $operation $context) ($operation+' empty') 'Resident output shape';$count++
}

# Producer challenge and transition publication.
$challenge=Join-Path $scratch 'challenge.json';Write-Text $challenge ('{"schema":"c1pe-challenge-v1","nonce":"'+$nonce+'"}')
$case=New-Case @(@{value='{"nonce":"'+$nonce+'","name":"post-arm.json"}'})
$null=Collected (Invoke-Case $case 'challenge' $challenge) 'challenge'
Need ($case.plan.calls[0].args[3] -ceq 'post-arm.json') 'Challenge name';$count++
$transition=Join-Path $scratch 'transition.json';Write-Text $transition ('{"schema":"c1pe-transition-v1","nonce":"'+$nonce+'"}')
$case=New-Case @(@{value='{"nonce":"'+$nonce+'","name":"transition.json"}'})
$null=Collected (Invoke-Case $case 'transition' $transition) 'transition';$count++
$wrong=Join-Path $scratch 'challenge-wrong.json';Write-Text $wrong ('{"schema":"c1pe-challenge-v1"}')
$case=New-Case @()
Failed (Invoke-Case $case 'challenge' $wrong) 'challenge without nonce' 'nonce'
Need ($case.plan.calls.Count -eq 0) 'Challenge reached the guest';$count++

# Owner transport fixture.
function New-OwnerTransport([string]$Name){
 $ot=Join-Path $scratch $Name
 foreach($d in 'commands','responses','proofs','samples','deployment'){$null=New-Item -ItemType Directory -Path (Join-Path $ot $d)}
 Write-Text (Join-Path $ot 'deployment/owner-supervisor.ps1') '# inert supervisor'
 Write-Text (Join-Path $ot 'deployment/full300-owner.exe') 'inert owner'
 $files=@(foreach($n in 'owner-supervisor.ps1','full300-owner.exe'){$b=[IO.File]::ReadAllBytes((Join-Path $ot "deployment/$n"));'{"name":"'+$n+'","sha256":"'+(Get-OwnerSHA256 $b)+'","length":'+$b.Length+'}'})
 Write-Text (Join-Path $ot 'deployment.json') ('{"files":['+($files -join ',')+']}')
 $ledger=Get-OwnerSHA256 ([IO.File]::ReadAllBytes((Join-Path $ot 'deployment.json')))
 $sup=Get-OwnerSHA256 ([IO.File]::ReadAllBytes((Join-Path $ot 'deployment/owner-supervisor.ps1')))
 $own=Get-OwnerSHA256 ([IO.File]::ReadAllBytes((Join-Path $ot 'deployment/full300-owner.exe')))
 Write-Text (Join-Path $ot 'config.json') ('{"schema":"full300-owner-config-v1","nonce":"'+$nonce+'","vm":"<LAB_VM_ID>","guest":"<LAB_GUEST_NAME>","principalName":"<LAB_GUEST_NAME>\\test","principalSid":"S-1-5-21-inert","taskName":"BimeronFull300Owner-'+$nonce+'","ownerSHA256":"'+$own+'","supervisorSHA256":"'+$sup+'","ledgerSHA256":"'+$ledger+'"}')
 return $ot
}
function Config-Hash($Ot){return Get-OwnerSHA256 ([IO.File]::ReadAllBytes((Join-Path $Ot 'config.json')))}
function Write-Command($Ot,[int]$Seq,[string]$Op,[string]$Body){
 $path=Join-Path $Ot ('commands/{0:D8}.json' -f $Seq)
 Write-Text $path ('{"schema":"full300-owner-command-v1","nonce":"'+$nonce+'","configSHA256":"'+(Config-Hash $Ot)+'","seq":'+$Seq+',"op":"'+$Op+'","body":'+$Body+'}')
 return $path
}
function Ref($Ot,[string]$Dir,[string]$Name,[string]$Text){
 Write-Text (Join-Path $Ot "$Dir/$Name") $Text;$b=[IO.File]::ReadAllBytes((Join-Path $Ot "$Dir/$Name"))
 return [pscustomobject]@{name=$Name;sha256=(Get-OwnerSHA256 $b);length=[long]$b.Length}
}
function RefJson($Ref){return '{"name":"'+$Ref.name+'","sha256":"'+$Ref.sha256+'","length":'+$Ref.length+'}'}
function Bundle($Ot,[string]$CommandPath,[string]$Op,[string]$State,[object[]]$Files){
 $raw=[IO.File]::ReadAllBytes($CommandPath);$cmd=$utf8.GetString($raw)|ConvertFrom-Json
 $Files=@($Files|Where-Object {$null -ne $_})
 $refs=@($Files|ForEach-Object {RefJson $_.ref}) -join ','
 $text='{"schema":"full300-owner-response-v1","nonce":"'+$nonce+'","configSHA256":"'+(Config-Hash $Ot)+'","seq":'+$cmd.seq+',"commandSHA256":"'+(Get-OwnerSHA256 $raw)+'","outcome":"accepted","state":"'+$State+'","owner":null,"refs":['+$refs+'],"error":null}'
 $list=[Collections.ArrayList]::new();foreach($f in $Files){$null=$list.Add($f)}
 return @{text=$text;value=@{bytes=(Bytes $text);files=$list}}
}

# Preflight: deployment, registration, Run intent and supervisor-once archive.
$ot=New-OwnerTransport 'preflight'
$once=Bytes '{"schema":"inert-once"}'
$case=New-Case @(@{value=@{xml='<Task/>';sddl='D:P';fileSddl='O:BA'}},@{value='{4D8B7BAF-A48B-43EA-80AF-9505B1502AC0}'},@{value=$once})
$text=Collected (Invoke-Case $case 'preflight' (Join-Path $ot 'config.json')) 'preflight'
Need ($text -ceq '{"schema":"inert-once"}' -and (Test-Path -LiteralPath (Join-Path $ot 'task-instance.json')) -and (Test-Path -LiteralPath (Join-Path $ot 'task-start-intent.json')) -and (Test-Path -LiteralPath (Join-Path $ot 'proofs/supervisor-once.json'))) 'Preflight archive'
Need (@($case.plan.calls[0].args[4]).Count -eq 2) 'Preflight deployment files';$count++
$ot=New-OwnerTransport 'preflight-null'
$case=New-Case @(@{value=$null})
Failed (Invoke-Case $case 'preflight' (Join-Path $ot 'config.json')) 'preflight null registration' 'registration'
Need (!(Test-Path -LiteralPath (Join-Path $ot 'task-start-intent.json'))) 'Run intent after empty registration';$count++

# Submit operations: {} bodies, single-element refs, empty refs, transitive proofs.
$ot=New-OwnerTransport 'submit'
foreach($op in @('sample','seal-no-launch')){
 $case=New-Case @()
 $path=Write-Command $ot ($(if($op -ceq 'sample'){1}else{2})) $op '{}'
 $files=if($op -ceq 'seal-no-launch'){@(@{dir='proofs';ref=(Ref $ot 'proofs' 'no-launch.json' ('{"schema":"full300-no-launch-v1","nonce":"'+$nonce+'","configSHA256":"'+(Config-Hash $ot)+'","supervisorOnceSHA256":"'+('d'*64)+'"}'));bytes=$null})}else{@()}
 $files=@($files|Where-Object {$null -ne $_})
 foreach($f in $files){$f.bytes=[IO.File]::ReadAllBytes((Join-Path $ot "proofs/$($f.ref.name)"))}
 $b=Bundle $ot $path $op 'SEALED_NO_LAUNCH' $files
 $null=$case.plan.queue.Add(@{none=$true});$null=$case.plan.queue.Add(@{value=$b.value})
 Need ((Collected (Invoke-Case $case $op $path) $op) -ceq $b.text) ($op+' response')
 Need (@($case.plan.calls[0].args[2]).Count -eq 0) ($op+' unexpected refs');$count++
 if($op -ceq 'seal-no-launch'){
  # Read-only fetch of the same original command on the next sequence.
  $null=$case.plan.queue.Add(@{value=$b.value})
  Need ((Collected (Invoke-Case $case $op $path 'fetch') ($op+' fetch')) -ceq $b.text) 'seal-no-launch fetch';$count++
 }
}
$request=Ref $ot 'proofs' 'cleanup-request.json' '{"inert":true}'
$drain=Ref $ot 'proofs' 'drain.json' ('{"schema":"full300-drain-v1","inner":'+(RefJson (Ref $ot 'proofs' 'reader-closures.json' '{"schema":"full300-reader-closures-v1","items":[]}'))+'}')
$path=Write-Command $ot 3 'cleanup' ('{"request":'+(RefJson $request)+',"drain":'+(RefJson $drain)+'}')
$b=Bundle $ot $path 'cleanup' 'CLEANUP' @()
$case=New-Case @(@{none=$true},@{value=$b.value})
$null=Collected (Invoke-Case $case 'cleanup' $path) 'cleanup'
Need (@($case.plan.calls[0].args[2]).Count -eq 3) 'Transitive cleanup closure';$count++
$case=New-Case @(@{none=$true},@{value=$null})
Failed (Invoke-Case $case 'sample' (Write-Command $ot 4 'sample' '{}')) 'sample null bundle' 'Response bundle';$count++
$case=New-Case @(@{none=$true},@{value=@{bytes=(Bytes '{}');files=[Collections.ArrayList]::new()}})
Failed (Invoke-Case $case 'sample' (Write-Command $ot 5 'sample' '{}')) 'sample empty response' 'nonce';$count++
$case=New-Case @(@{none=$true},@{value=@{bytes=(Bytes '{}')}})
Failed (Invoke-Case $case 'sample' (Write-Command $ot 6 'sample' '{}')) 'sample bundle without files' 'Response bundle';$count++

# exit-supervisor: Submit-OwnerCommand then Complete-OwnerFinal (noLaunch).
$ot=New-OwnerTransport 'exit'
$onceHash='d'*64;$cfg=Config-Hash $ot
$noLaunch=Ref $ot 'proofs' 'no-launch.json' ('{"schema":"full300-no-launch-v1","nonce":"'+$nonce+'","configSHA256":"'+$cfg+'","supervisorOnceSHA256":"'+$onceHash+'","launchAttempted":false,"sealed":true}')
Write-Text (Join-Path $ot 'task-registration.json') '{"xml":"<Task/>","sddl":"D:P","fileSddl":"O:BA"}'
Write-Text (Join-Path $ot 'task-instance.json') '{"instanceGuid":"{4D8B7BAF-A48B-43EA-80AF-9505B1502AC0}"}'
$path=Write-Command $ot 2 'exit-supervisor' ('{"noLaunch":'+(RefJson $noLaunch)+'}')
$ready=Bytes ('{"schema":"full300-supervisor-exit-v1","nonce":"'+$nonce+'","configSHA256":"'+$cfg+'","supervisorOnceSHA256":"'+$onceHash+'","exitCommandSHA256":"'+(Get-OwnerSHA256 ([IO.File]::ReadAllBytes($path)))+'","proofSHA256":"'+$noLaunch.sha256+'","reason":"sealed-no-launch"}')
$readyRef=[pscustomobject]@{name='supervisor-exit-ready.json';sha256=(Get-OwnerSHA256 $ready);length=[long]$ready.Length}
$b=Bundle $ot $path 'exit-supervisor' 'EXIT_READY' @(@{dir='proofs';ref=$readyRef;bytes=$ready})
$case=New-Case @(@{none=$true},@{value=$b.value},@{value=$ready},@{value=@{state=3;instanceGuids=@();lastTaskResult=0}},@{value='inert delete output'})
Need ((Collected (Invoke-Case $case 'exit-supervisor' $path) 'exit-supervisor') -ceq $b.text) 'exit-supervisor response'
Need ((Test-Path -LiteralPath (Join-Path $ot 'task-final.json')) -and $case.plan.calls.Count -eq 5 -and $case.plan.calls[4].args[4] -eq $true) 'exit-supervisor final/delete';$count++
$ot=New-OwnerTransport 'exit-mismatch';$cfg=Config-Hash $ot
$noLaunch=Ref $ot 'proofs' 'no-launch.json' ('{"schema":"full300-no-launch-v1","nonce":"'+$nonce+'","configSHA256":"'+$cfg+'"}')
Write-Text (Join-Path $ot 'task-registration.json') '{}';Write-Text (Join-Path $ot 'task-instance.json') '{"instanceGuid":"{4D8B7BAF-A48B-43EA-80AF-9505B1502AC0}"}'
$path=Write-Command $ot 2 'exit-supervisor' ('{"noLaunch":'+(RefJson $noLaunch)+'}')
$b=Bundle $ot $path 'exit-supervisor' 'EXIT_READY' @()
$case=New-Case @(@{none=$true},@{value=$b.value},@{value=$ready})
Failed (Invoke-Case $case 'exit-supervisor' $path) 'exit-supervisor proof without once hash' 'HOLD: exit-ready binding mismatch'
Need (!(Test-Path -LiteralPath (Join-Path $ot 'task-final.json')) -and $case.plan.calls.Count -eq 3) 'Deletion after binding mismatch';$count++

# Unknown sessions are retained; close and finish under strict mode.
$state=New-ResidentGuestState $nonce $configHash
$state.session=[pscustomobject]@{State='Opened'};$state.sessionAttempted=$true
function Remove-PSSession {param($Session,$ErrorAction)$Session.State='Closed'}
$closed=Close-ResidentOriginal $state {param($i,$raw)}
Need ($closed.sessionState -ceq 'Closed' -and $state.closed) 'Strict close';$count++
$state=New-ResidentGuestState $nonce $configHash
Need ((Close-ResidentOriginal $state {param($i,$raw)}).pending -eq 0) 'Strict close without session';$count++

# Atomic create-once resident publication (live run 7a85aad9: a poller read a
# created but still empty resident-ready.json).
$pub=Join-Path $scratch 'publish';$null=New-Item -ItemType Directory -Path $pub
Publish-ResidentBytesOnce $pub 'resident-ready.json' (Bytes '{"a":1}')
Need ([IO.File]::ReadAllText((Join-Path $pub 'resident-ready.json')) -ceq '{"a":1}') 'Atomic publication bytes';$count++
Publish-ResidentBytesOnce $pub 'resident-ready.json' (Bytes '{"a":1}')
Need (@(Get-ChildItem -LiteralPath $pub -Force).Count -eq 1) 'Idempotent publication left a temporary';$count++
$refused=$false;try{Publish-ResidentBytesOnce $pub 'resident-ready.json' (Bytes '{"a":2}')}catch{$refused=$_.Exception.Message -ceq 'Resident publication conflict'}
Need ($refused -and [IO.File]::ReadAllText((Join-Path $pub 'resident-ready.json')) -ceq '{"a":1}') 'Different bytes must be refused';$count++
$refused=$false;try{Publish-ResidentBytesOnce $pub '../x.json' (Bytes '{}')}catch{$refused=$_.Exception.Message -ceq 'Resident filename'}
Need $refused 'Resident filename';$count++
# A final name appearing while the temporary is written is compared, never replaced.
[IO.File]::WriteAllBytes((Join-Path $pub 'resident-closed.json'),(Bytes '{"b":0}'))
$refused=$false;try{Publish-ResidentBytesOnce $pub 'resident-closed.json' (Bytes '{"b":1}')}catch{$refused=$true}
Need ($refused -and [IO.File]::ReadAllText((Join-Path $pub 'resident-closed.json')) -ceq '{"b":0}') 'Existing final file replaced';$count++
Need (@(Get-ChildItem -LiteralPath $pub -Force -Filter '*.tmp').Count -eq 0) 'Temporary left behind';$count++
# Reader: absent and zero-length are "not yet"; complete bytes are returned.
Need ($null -eq (Read-ResidentPublished (Join-Path $pub 'absent.json'))) 'Absent publication';$count++
[IO.File]::WriteAllBytes((Join-Path $pub 'empty.json'),[byte[]]@())
Need ($null -eq (Read-ResidentPublished (Join-Path $pub 'empty.json'))) 'Empty publication is not yet';$count++
$read=Read-ResidentPublished (Join-Path $pub 'resident-ready.json')
Need ($read -is [byte[]] -and $read.Length -eq 7) 'Complete publication bytes';$count++
# Temporary names stay short (MAX_PATH budget): '.' + 8 hex + '.tmp'.
$src=Get-Content -LiteralPath "$PSScriptRoot/resident-guest.ps1" -Raw
Need ($src.Contains("('.'+[Guid]::NewGuid().ToString('N').Substring(0,8)+'.tmp')")) 'Short temporary name';$count++

# The real resident-main loop under strict mode: readiness, close, finish.
$root=Join-Path $scratch 'resident-root';$null=New-Item -ItemType Directory -Path $root
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetSecurityDescriptorSddlForm("O:$($sid)D:P(A;OICI;FA;;;$sid)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
Set-Acl -LiteralPath $root -AclObject $acl
$shell=(Get-Process -Id $PID).Path
$process=Start-Process -FilePath $shell -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"`"$PSScriptRoot/resident-main.ps1`"",'-Root',"`"$root`"",'-Nonce',$nonce,'-ConfigSHA256',$configHash) -PassThru -WindowStyle Hidden
function Wait-File([string]$Path){$w=[Diagnostics.Stopwatch]::StartNew();while(!(Test-Path -LiteralPath $Path)){if($w.Elapsed.TotalSeconds -gt 60 -or $process.HasExited){throw ('Resident main did not publish '+[IO.Path]::GetFileName($Path))};Start-Sleep -Milliseconds 50}}
try{
 Wait-File (Join-Path $root 'resident-ready.json')
 [IO.File]::WriteAllBytes((Join-Path $root 'resident-close-request.json'),[byte[]]@());Start-Sleep -Milliseconds 300
 Need (!(Test-Path -LiteralPath (Join-Path $root 'resident-closed.json'))) 'Empty close request acted on'
 Write-Text (Join-Path $root 'resident-close-request.json') ('{"schema":"fresh-resident-close-v1","nonce":"'+$nonce+'","configSHA256":"'+$configHash+'","lastSequence":0}')
 Wait-File (Join-Path $root 'resident-closed.json')
 $closure=Get-OwnerSHA256 ([IO.File]::ReadAllBytes((Join-Path $root 'resident-closed.json')))
 Write-Text (Join-Path $root 'resident-finish-request.json') ('{"schema":"fresh-resident-finish-v1","nonce":"'+$nonce+'","configSHA256":"'+$configHash+'","closureSHA256":"'+$closure+'"}')
 Need ($process.WaitForExit(60000) -and $process.ExitCode -eq 0) 'Resident main did not finish'
 Need (Test-Path -LiteralPath (Join-Path $root 'resident-finished.json')) 'Resident finish record'
 Need (@(Get-ChildItem -LiteralPath $root -Force -Filter '*.tmp').Count -eq 0) 'Resident main left a temporary'
}finally{if(!$process.HasExited){$process.Kill()}}
$count++
'PASS resident strict-mode operations: '+$count+' cases'
