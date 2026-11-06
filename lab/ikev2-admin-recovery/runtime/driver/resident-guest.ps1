# Original guest-control owner. Dot-source is inert; production entry is separate.
Set-StrictMode -Version Latest
function New-ResidentGuestState([string]$Nonce,[string]$ConfigHash) {
 if($Nonce -cnotmatch '^[a-f0-9]{64}$' -or $ConfigHash -cnotmatch '^[a-f0-9]{64}$'){throw 'Resident binding'}
 return [hashtable]::Synchronized(@{nonce=$Nonce;configSHA256=$ConfigHash;session=$null;sessionAttempted=$false;sessionValidated=$false;closing=$false;closeAttempted=$false;closed=$false;finished=$false;sequence=0L;requests=@{};active=$null;failure=$null;worker=$null;runspace=$null})
}
function Invoke-ResidentGuestBody($State,$Request) {
 # Runs only in the retained original runspace. Requests select fixed existing
 # functions; they never contain script text, session credentials or a PID kill.
 $Nonce=$State.nonce;$root="C:/BimeronFull300/$Nonce"
 $path=$Request.path
 if((Get-OwnerSHA256 ([IO.File]::ReadAllBytes($path))) -cne $Request.requestSHA256){throw 'Resident request bytes changed'}
 if(!$State.sessionValidated){
  if($State.sessionAttempted){throw 'Session admission unresolved; original retained'}
  $State.session=Open-OwnerSession $State
  $State.sessionValidated=$true
 }
 $session=$State.session
 if($Request.operation -ceq 'restore-session-policy'){
  return Invoke-Command -Session $session -ArgumentList $Nonce -ScriptBlock {
   param($nonce)
   $ErrorActionPreference='Stop'
   $original=Get-Variable BimeronOriginalProcessPolicy -Scope Global -ValueOnly -ErrorAction Stop
   if($original.nonce -cne $nonce -or $original.restored -or [string](Get-ExecutionPolicy -Scope Process) -cne 'Bypass'){throw 'Original policy restoration binding'}
   # Reserve in the original remote owner before the sole restoration effect.
   $original.restored=$true
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy $original.value -Force
   if([string](Get-ExecutionPolicy -Scope Process) -cne $original.value){throw 'Original Process policy readback'}
   @{nonce=$nonce;scope='Process';value=$original.value;restored=$true}|ConvertTo-Json -Compress
  }
 }
 if($Request.operation -cin @('guest','services','absence')){
  . "$PSScriptRoot/admin-readback.ps1"
  return Read-AdministrativeGuest $session $Request.operation
 }
 if($Request.operation -ceq 'principal'){
  return Invoke-Command -Session $session -ScriptBlock {([Security.Principal.NTAccount]'<LAB_GUEST_NAME>\test').Translate([Security.Principal.SecurityIdentifier]).Value}
 }
 if($Request.operation -cin @('integration','ready','clock')){
  return & "$PSScriptRoot/guest-read.ps1" -Mode $Request.operation -Nonce $Nonce -OwnedSession $session
 }
 if($Request.operation -cin @('challenge','transition')){
  return Publish-ProducerChallenge $session $root $path $Request.operation
 }
 if($Request.mode -ceq 'fetch') {
  $envelope=Assert-StrictOwnerJson ([IO.File]::ReadAllBytes($path))
  if($envelope.op -cnotin @('launch','sample','start','cleanup','seal-no-launch')){throw 'Unsafe resident fetch'}
  return Fetch-OwnerResponse $session $root $path
 }
 if($Request.operation -ceq 'preflight') {
  $null=Install-OwnerTask $session $root $path
  return Fetch-OwnerReady $session $root $path
 }
 $envelope=Assert-StrictOwnerJson ([IO.File]::ReadAllBytes($path))
 if($envelope.nonce -cne $Nonce -or $envelope.op -cne $Request.operation){throw 'Resident envelope mismatch'}
 $response=Submit-OwnerCommand $session $root $path
 # Complete-OwnerFinal publishes proofs only; its pipeline output must never
 # change the single resident response value.
 if($Request.operation -ceq 'exit-supervisor'){$null=Complete-OwnerFinal $session $root $path}
 return $response
}
function Get-ResidentResponse($State,$Record) {
 # One terminal record yields one published response. An unexpected output
 # shape is a terminal Failed outcome, never a silently repeated loop error.
 if($Record.state -cnotin @('Collected','Failed')){throw 'Resident response before terminal state'}
 if($Record.state -ceq 'Collected'){
  # EndInvoke yields PSObject wrappers (PowerShell 7 keeps them for -is).
  # No pipeline: a single returned array must stay one non-string item.
  $items=[Collections.ArrayList]::new()
  foreach($item in @($Record.output)){if($item -is [psobject]){$null=$items.Add($item.PSObject.BaseObject)}else{$null=$items.Add($item)}}
  if($items.Count -ne 1 -or $items[0] -isnot [string]){$Record.error='Resident output shape: '+$items.Count+' item(s)';$Record.state='Failed'}
 }
 $output=$null
 if($Record.state -ceq 'Collected'){$output=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($items[0]))}
 return @{schema='fresh-resident-response-v1';nonce=$State.nonce;configSHA256=$State.configSHA256;sequence=$Record.request.sequence;requestSHA256=$Record.request.requestSHA256;state=$Record.state;output=$output;error=$(if($Record.state -ceq 'Failed'){$Record.error}else{$null})}
}
function Get-ResidentErrorText($Failure,[int]$Limit=512) {
 # Diagnostic text only: innermost exception type/message plus script:line
 # (basename), control characters removed, bounded. Never script or secrets.
 if($null -eq $Failure){return $null}
 $exception=if($Failure -is [Management.Automation.ErrorRecord]){$Failure.Exception}else{$Failure}
 $where=$null
 if($Failure -is [Management.Automation.ErrorRecord] -and $null -ne $Failure.InvocationInfo -and $Failure.InvocationInfo.ScriptName){$where=$Failure.InvocationInfo}
 while($exception -is [Exception] -and $null -ne $exception.InnerException){$exception=$exception.InnerException}
 if($exception -is [Management.Automation.IContainsErrorRecord] -and $null -ne $exception.ErrorRecord.InvocationInfo -and $exception.ErrorRecord.InvocationInfo.ScriptName){$where=$exception.ErrorRecord.InvocationInfo}
 $text=if($exception -is [Exception]){$exception.GetType().Name+': '+$exception.Message}else{[string]$exception}
 if($null -ne $where){$text+=' @ '+[IO.Path]::GetFileName($where.ScriptName)+':'+$where.ScriptLineNumber}
 $text=($text -replace '[\p{C}]',' ').Trim()
 if($text.Length -gt $Limit){$text=$text.Substring(0,$Limit)}
 return $text
}
function Start-ResidentInvocation($State,$Request) {
 if($null -eq $State.runspace){
  $State.runspace=[RunspaceFactory]::CreateRunspace();$State.runspace.Open()
 }
 $ps=[PowerShell]::Create();$ps.Runspace=$State.runspace
 # Capture the owning object before any invocation can throw.
 $State.active.ps=$ps
 $null=$ps.AddScript({param($shared,$request,$driver)
  $ErrorActionPreference='Stop'
  . (Join-Path $driver 'protected-guest.ps1')
  . (Join-Path $driver 'resident-guest.ps1')
  Invoke-ResidentGuestBody $shared $request
 }.ToString()).AddArgument($State).AddArgument($Request).AddArgument($PSScriptRoot)
 return $ps.BeginInvoke()
}
function Submit-ResidentRequest($State,$Request,[scriptblock]$Reserve) {
 $expected=@('schema','nonce','configSHA256','sequence','mode','operation','path','requestSHA256')
 if(@($Request.Keys).Count -ne $expected.Count -or @($Request.Keys|Where-Object {$_ -cnotin $expected}).Count){throw 'Resident request fields'}
 if($Request.schema -cne 'fresh-resident-request-v1' -or $Request.nonce -cne $State.nonce -or $Request.configSHA256 -cne $State.configSHA256){throw 'Resident request binding'}
 if($Request.sequence -isnot [long] -and $Request.sequence -isnot [int]){throw 'Resident sequence type'}
 if($Request.mode -cnotin @('submit','fetch') -or $Request.operation -cnotin @('principal','integration','ready','clock','guest','services','absence','restore-session-policy','challenge','transition','preflight','launch','sample','start','cleanup','seal-no-launch','exit-supervisor')){throw 'Resident operation'}
 if($Request.mode -ceq 'fetch' -and $Request.operation -cnotin @('launch','sample','start','cleanup','seal-no-launch')){throw 'Unsafe resident fetch'}
 $fingerprint=$Request|ConvertTo-Json -Depth 10 -Compress
 $id=[long]$Request.sequence
 if($State.requests.ContainsKey($id)){
  if($State.requests[$id].fingerprint -cne $fingerprint){throw 'Resident request conflict'}
  if($State.requests[$id].state -ceq 'Reserved'){return Start-ResidentReserved $State $State.requests[$id] $Reserve}
  return $State.requests[$id]
 }
 if($State.closing -or $State.finished -or $id -ne $State.sequence+1){throw 'Resident admission closed/sequence'}
 if($null -ne $State.active -and $State.active.state -cnotin @('Collected','Failed')){throw 'Original invocation outstanding'}
 if($Request.mode -ceq 'fetch'){
  $original=@($State.requests.Values|Where-Object {$_.request.mode -ceq 'submit' -and $_.request.path -ceq $Request.path -and $_.request.requestSHA256 -ceq $Request.requestSHA256 -and $_.request.operation -ceq $Request.operation})
  if($original.Count -ne 1 -or $original[0].state -cnotin @('Collected','Failed')){throw 'Original fetch binding/terminal missing'}
 }
 # Failed terminal requests may only be observed via existing read-only fetch,
 # never re-submitted as a new sequence. Mutations have a per-operation ledger.
 foreach($prior in $State.requests.Values){
  if($Request.mode -ceq 'submit' -and $prior.request.mode -ceq 'submit' -and $prior.request.operation -ceq $Request.operation -and $Request.operation -cnotin @('sample','integration','ready','clock','guest','services','absence')){throw 'Resident mutation already attempted'}
 }
 $record=@{fingerprint=$fingerprint;request=$Request;state='Reserved';ps=$null;handle=$null;output=$null;errors=@();error=$null;collectAttempted=$false}
 $State.requests[$id]=$record;$State.active=$record;$State.sequence=$id
 return Start-ResidentReserved $State $record $Reserve
}
function Start-ResidentReserved($State,$Record,[scriptblock]$Reserve) {
 if($Record.state -cne 'Reserved'){throw 'Original invocation already attempted'}
 # A storage failure here is positively before BeginInvoke. Retry publishes the
 # same reservation, then enters the same original invocation exactly once.
 & $Reserve $Record.request.sequence $Record.fingerprint
 try{$Record.handle=Start-ResidentInvocation $State $Record.request;$Record.state='Pending'}catch{$Record.state='Unknown';$State.failure=[string]$_.Exception.Message;throw}
 return $Record
}
function Collect-ResidentOriginal($State) {
 $record=$State.active
 if($null -eq $record){throw 'No original invocation'}
 if($record.state -cin @('Collected','Failed')){return $record}
 if($record.state -cne 'Pending' -or $null -eq $record.handle){throw 'Original invocation ownership unknown'}
 if(!$record.handle.IsCompleted){return $record}
 if($record.collectAttempted){throw 'Original collection unknown; no EndInvoke replay'}
 $record.collectAttempted=$true
 try{
  $record.output=@($record.ps.EndInvoke($record.handle))
  $record.errors=@($record.ps.Streams.Error)
  if($record.errors.Count){$record.error=Get-ResidentErrorText $record.errors[0];$record.state='Failed'}else{$record.state='Collected'}
 }catch{$record.errors+=,$_ ;$record.error=Get-ResidentErrorText $_;$record.state='Failed';$State.failure=[string]$_.Exception.Message}
 return $record
}
function Close-ResidentOriginal($State,[scriptblock]$Reserve) {
 $State.closing=$true
 foreach($record in $State.requests.Values){if($record.state -cnotin @('Collected','Failed')){throw 'Original work outstanding; session retained'}}
 if(!$State.closeAttempted){
  & $Reserve 'session-close' 'original-session-only'
  $State.closeAttempted=$true
  if($null -ne $State.session){Remove-PSSession -Session $State.session -ErrorAction Stop}
 }
 if($null -eq $State.session){
  if($State.sessionAttempted){throw 'Original session creation unknown'}
 }elseif($State.session.State -cne 'Closed'){throw 'Original session closure unproven'}
 $State.closed=$true
 return @{schema='fresh-resident-closed-v1';nonce=$State.nonce;configSHA256=$State.configSHA256;sessionState='Closed';pending=0;normalCleanupSucceeded=$false}
}
# Atomic create-once publication into the resident guest-control root. Bytes
# go to a short same-directory temporary, are flushed, then moved without
# overwrite, so a poller sees either no file or the complete file. An existing
# final file with identical bytes is idempotent; different bytes are refused.
function Publish-ResidentBytesOnce([string]$Root,[string]$Name,[byte[]]$Bytes) {
 if($Name -cnotmatch '^[a-z][a-z0-9-]*\.json$'){throw 'Resident filename'}
 if($null -eq $Bytes){throw 'Resident publication bytes'}
 $path=Join-Path $Root $Name
 $digest=Get-OwnerSHA256 $Bytes
 if([IO.File]::Exists($path)){if((Get-OwnerSHA256 ([IO.File]::ReadAllBytes($path))) -cne $digest){throw 'Resident publication conflict'};return}
 $temporary=$null
 try{
  for($attempt=0;$attempt -lt 4 -and $null -eq $temporary;$attempt++){
   $candidate=Join-Path $Root ('.'+[Guid]::NewGuid().ToString('N').Substring(0,8)+'.tmp')
   try{$stream=[IO.File]::Open($candidate,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$temporary=$candidate}catch [IO.IOException]{if(![IO.File]::Exists($candidate)){throw}}
  }
  if($null -eq $temporary){throw 'Resident publication temporary collision'}
  try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  # File.Move never replaces an existing destination (both .NET Framework and .NET).
  try{[IO.File]::Move($temporary,$path);$temporary=$null}catch [IO.IOException]{if(![IO.File]::Exists($path)){throw}}
  if((Get-OwnerSHA256 ([IO.File]::ReadAllBytes($path))) -cne $digest){throw 'Resident publication conflict'}
 }finally{if($null -ne $temporary -and [IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
}
# A polled owner publication that is absent or still zero-length is "not yet".
function Read-ResidentPublished([string]$Path) {
 if(![IO.File]::Exists($Path)){return $null}
 $bytes=[IO.File]::ReadAllBytes($Path)
 if($bytes.Length -eq 0){return $null}
 return ,$bytes
}
