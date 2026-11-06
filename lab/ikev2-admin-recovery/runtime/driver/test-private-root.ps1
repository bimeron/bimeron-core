param([Parameter(Mandatory=$true)][string]$Driver,[Parameter(Mandatory=$true)][string]$Work)
# Hermetic: the driver scripts run against a cp-<16 hex> private run root with
# session cmdlets stubbed. No VM, PSSession, credential or network is reached.
# Windows PowerShell 5.1 only: the driver always runs these scripts there.
$ErrorActionPreference='Stop'
$nonce='c0ffee'+('1'*58)
$here=Join-Path $Work 'driver';$null=New-Item -ItemType Directory $here
foreach($name in @('guest-read.ps1','prepare-task.ps1','cancellation.ps1','file-sha256.ps1','Clock.cs','Journal.cs','reader-health.ps1','persistent-reader.ps1')){
 Copy-Item -LiteralPath (Join-Path $Driver $name) -Destination (Join-Path $here $name)
}
. (Join-Path $here 'cancellation.ps1')
function New-Root([string]$Name,$Identity) {
 $path=Join-Path $here $Name;$null=New-Item -ItemType Directory $path
 if($null -ne $Identity){[IO.File]::WriteAllText((Join-Path $path 'run-identity.json'),($Identity|ConvertTo-Json -Compress))}
 return $path
}
$rootName='cp-'+$nonce.Substring(0,16)
$root=New-Root $rootName @{schema='fresh-admin-run-identity-v1';nonce=$nonce;rootName=$rootName}
$invocations=[Collections.ArrayList]::new()
function Import-Clixml {param([Parameter(ValueFromRemainingArguments=$true)]$Rest) return 'offline-credential'}
function New-PSSession {param([Parameter(ValueFromRemainingArguments=$true)]$Rest) return [pscustomobject]@{InstanceId=[Guid]::NewGuid();State='Opened'}}
function Remove-PSSession {param([Parameter(ValueFromRemainingArguments=$true)]$Rest)}
function Invoke-Command {
 param($Session,[object[]]$ArgumentList,[scriptblock]$ScriptBlock)
 $null=$invocations.Add(@($ArgumentList))
 if($ArgumentList[0] -eq 'stop'){return (@{nonce=$ArgumentList[1];delivered=$true;requestId=$ArgumentList[2].requestId;stopRequest=$ArgumentList[2];adoptedRequest=$ArgumentList[2]}|ConvertTo-Json -Compress)}
}
function Expect-Throw([string]$Pattern,[scriptblock]$Body) {
 try{& $Body;$raised=$null}catch{$raised=$_.Exception.Message}
 if($null -eq $raised -or $raised -notmatch $Pattern){throw "Expected refusal '$Pattern', got '$raised'"}
}
$guest=Join-Path $here 'guest-read.ps1'

# restore-permit: read from the admitted cp root.
Publish-ProbeJson (Join-Path $root 'restore-permit.json') @{schema=1;nonce=$nonce;readersDrained=$true}
$permit=(& $guest -Mode restore-permit -Nonce $nonce -ControlPath $root)|ConvertFrom-Json
if($permit.nonce -cne $nonce -or $permit.readersDrained -ne $true){throw 'restore-permit from cp root'}
'PASS restore-permit'

# stop: the host request in the cp root is delivered to the (stubbed) session.
$request=[pscustomobject]@{schema=1;nonce=$nonce;requestId='offline-request';reasonCode='offline';requestedUtc=[DateTime]::UtcNow.ToString('o')}
if(!$request.requestedUtc.EndsWith('Z')){$request.requestedUtc=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')}
Publish-ProbeStop (Join-Path $root 'stop-request.json') $request $nonce
$ack=(& $guest -Mode stop -Nonce $nonce -ControlPath $root)|ConvertFrom-Json
if($ack.delivered -ne $true -or $ack.requestId -cne 'offline-request'){throw 'stop ack'}
$sent=$invocations[$invocations.Count-1]
if($sent[0] -cne 'stop' -or $sent[2].requestId -cne 'offline-request'){throw 'stop request not delivered from cp root'}
'PASS stop'

# persistent: the session-open acknowledgement is published in the cp root.
$null=& $guest -Mode persistent -Nonce $nonce -ControlPath $root -TestRole supervisor
$marker=[IO.File]::ReadAllText((Join-Path $root 'reader-supervisor-session-open.json'))|ConvertFrom-Json
if($marker.nonce -cne $nonce -or $marker.role -cne 'supervisor'){throw 'session-open marker'}
'PASS persistent'

# Refusals: no root, legacy template name, wrong binding, outside the driver.
Expect-Throw 'ControlPath required' {& $guest -Mode restore-permit -Nonce $nonce}
Expect-Throw 'ControlPath required' {& $guest -Mode stop -Nonce $nonce}
$legacy=New-Root ('capture-prep-'+$nonce) $null
Publish-ProbeJson (Join-Path $legacy 'restore-permit.json') @{schema=1;nonce=$nonce;readersDrained=$true}
Expect-Throw 'Private run identity missing' {& $guest -Mode restore-permit -Nonce $nonce -ControlPath $legacy}
$wrongName='cp-'+('2'*16)
$wrong=New-Root $wrongName @{schema='fresh-admin-run-identity-v1';nonce=$nonce;rootName=$rootName}
Expect-Throw 'Private run identity binding' {& $guest -Mode restore-permit -Nonce $nonce -ControlPath $wrong}
$other='d'*64
Expect-Throw 'Private run identity binding' {& $guest -Mode restore-permit -Nonce $other -ControlPath $root}
$outside=Join-Path $Work $rootName;$null=New-Item -ItemType Directory $outside
Copy-Item -LiteralPath (Join-Path $root 'run-identity.json') -Destination $outside
Expect-Throw 'beside the driver' {& $guest -Mode restore-permit -Nonce $nonce -ControlPath $outside}
'PASS guest-read refusals'

# prepare-task: the cp root passes the root check and reaches the next gate
# (source freeze) without any session; bad roots are refused first.
$task=Join-Path $here 'prepare-task.ps1'
[IO.File]::WriteAllText((Join-Path $root 'preparation-source.ps1'),'# a different frozen source')
Expect-Throw 'Preparation source freeze mismatch' {& $task -Nonce $nonce -ControlPath $root}
Expect-Throw 'ControlPath required' {& $task -Nonce $nonce}
Expect-Throw 'Private run identity missing' {& $task -Nonce $nonce -ControlPath $legacy}
Expect-Throw 'Private run identity binding' {& $task -Nonce $nonce -ControlPath $wrong}
'PASS prepare-task'
