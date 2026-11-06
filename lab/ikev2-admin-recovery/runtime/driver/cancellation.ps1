function Read-ProbeStop([string]$Path,[string]$Nonce) {
 if(!(Test-Path -LiteralPath $Path)){return $null}
 $r=[IO.File]::ReadAllText($Path)|ConvertFrom-Json
 Assert-ProbeStop $r $Nonce
 return $r
}
function Assert-ProbeStop($r,[string]$Nonce) {
 if(($r.schema -isnot [int] -and $r.schema -isnot [long]) -or $r.schema -ne 1 -or $r.nonce -cne $Nonce -or $Nonce -cnotmatch '^[a-f0-9]{64}$' -or
   (($r.PSObject.Properties.Name|Sort-Object) -join ',') -cne 'nonce,reasonCode,requestedUtc,requestId,schema'){throw 'Invalid stop request binding/schema'}
 foreach($key in @('requestId','reasonCode','requestedUtc')){if($r.$key -isnot [string] -or [string]::IsNullOrWhiteSpace($r.$key)){throw 'Invalid stop request field'}}
 $stamp=[DateTimeOffset]::MinValue
 if(!$r.requestedUtc.EndsWith('Z') -and !$r.requestedUtc.EndsWith('+00:00')){throw 'Stop timestamp must be UTC'}
 if(![DateTimeOffset]::TryParse($r.requestedUtc,[ref]$stamp)){throw 'Invalid stop timestamp'}
}
function Assert-ProbeRestorePermit($Permit,[string]$Nonce) {
 if(($Permit.schema -isnot [int] -and $Permit.schema -isnot [long]) -or $Permit.schema -ne 1 -or $Permit.nonce -cne $Nonce -or $Permit.readersDrained -isnot [bool] -or !$Permit.readersDrained -or (($Permit.PSObject.Properties.Name|Sort-Object) -join ',') -cne 'nonce,readersDrained,schema'){throw 'HOLD: invalid host restore permit'}
}
function Publish-ProbeJson([string]$Path,$Value) {
 $temporary=Join-Path ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))) ('p-'+[Guid]::NewGuid().ToString('N').Substring(0,16)+'.tmp')
 try{
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12 -Compress))
  $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  [IO.File]::Move($temporary,$Path)
 }finally{if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary}}
}
function Publish-ProbeStop([string]$Path,$Request,[string]$Nonce) {
 Assert-ProbeStop $Request $Nonce
 if(Test-Path -LiteralPath $Path){
  $existing=Read-ProbeStop $Path $Nonce
  foreach($key in @('schema','nonce','requestId','reasonCode','requestedUtc')){if($existing.$key -cne $Request.$key){throw 'Conflicting stop request'}}
  return
 }
 try{Publish-ProbeJson $Path $Request}catch{
  if(!(Test-Path -LiteralPath $Path)){throw}
  $existing=Read-ProbeStop $Path $Nonce
  foreach($key in @('schema','nonce','requestId','reasonCode','requestedUtc')){if($existing.$key -cne $Request.$key){throw 'Conflicting stop publication'}}
 }
 $null=Read-ProbeStop $Path $Nonce
}
function Get-ProbeTerminalDecision($Rows,$Producer,[string]$Nonce,[int]$Duration,$Request) {
 if(@($Rows).Count -lt 2){throw 'Terminal missing'}
 $first=$Rows[0];$last=$Rows[-1];$sequence=0
 foreach($row in $Rows){
  if($row.nonce -cne $Nonce -or $row.producer.pid -ne $Producer.pid -or $row.producer.start -cne $Producer.start -or $row.producer.sid -cne $Producer.sid -or $row.sequence -ne ($sequence+1)){throw 'Terminal identity/sequence mismatch'}
  $sequence=$row.sequence
 }
 if($first.kind -cne 'start' -or $last.kind -cne 'end' -or $last.target -cne 'all'){throw 'Terminal missing'}
 if($last.status -ceq 'cancelled'){
  if(!$Request -or $last.requestId -cne $Request.requestId){throw 'Cancellation request mismatch'}
  return 'cancelled'
 }
 if($last.status -cne 'complete' -or ($last.ticks-$first.ticks)/[Diagnostics.Stopwatch]::Frequency -lt $Duration){throw 'Terminal duration/status invalid'}
 return 'completed'
}
function Test-ProbeExitRace([string]$Message,$Pins) {
 # Only observation failures caused by an exited retained owner can be retried.
 $allowed=@('Process exited','Process exited during sample','Process liveness mismatch')
 return ($Message -cin $allowed -and @($Pins|Where-Object {!$_.Alive}).Count -gt 0)
}
function Test-ProbeTerminalTransition($Instance,$Launch,$Expected,$Pins) {
 if($Instance.guid -cne $Launch.guid -or $Instance.path -cne $Expected.registration.path -or ($Instance.engine -ne 0 -and $Instance.engine -ne $Launch.engine)){throw 'Scheduler terminal binding mismatch'}
 if($Instance.state -ne 4 -or $Instance.engine -eq 0){
  if(@($Pins).Count -ne 2 -or !@($Pins|Where-Object {!$_.Alive}).Count){throw 'Scheduler transition without retained exit'}
  return $true
 }
 return $false
}

function Assert-ProbeNonLivenessProvenance {
 param($Expected,$Registration,$Launch,$Instance,$Event,$Parent,$Producer,$Pinned)
 Assert-ProbeRegistration $Expected.registration $Registration
 if(!$Instance -or !$Event -or !$Parent -or !$Producer){throw 'Missing authoritative provenance observation'}
 if($Instance.guid -ne $Launch.guid -or $Instance.path -cne $Expected.registration.path -or $Instance.state -ne 4 -or $Instance.engine -ne $Launch.engine){throw 'Scheduler instance changed/not running'}
 if($Event.guid -ne $Launch.guid -or $Event.engine -ne $Launch.engine -or $Event.task -cne $Expected.registration.path -or $Event.action -cne $Expected.registration.action[0].Execute -or $Event.record -le $Launch.bookmark){throw 'Scheduler event200 mismatch'}
 if($Parent.pid -ne $Launch.engine -or $Producer.parent -ne $Parent.pid){throw 'Producer is not child of authoritative task action process'}
 foreach($pair in @(@($Parent,'cmd'),@($Producer,'powershell'))){
  $p=$pair[0];$image=$Expected.images.($pair[1])
  if($p.path -ine $image.path -or $p.sha256 -ine $image.sha256){throw 'Expected image mismatch'}
  if($p.sid -ne $Expected.registration.principal.sid -or $p.elevated -or $p.integrity -ne 'S-1-16-8192'){throw 'Expected ordinary token mismatch'}
  if(($p.arguments|ConvertTo-Json -Compress) -cne ($image.arguments|ConvertTo-Json -Compress)){throw 'Expected process arguments mismatch'}
 }
 if([DateTime]::Parse($Parent.start).ToUniversalTime() -lt [DateTime]::Parse($Launch.before).ToUniversalTime() -or [DateTime]::Parse($Producer.start).ToUniversalTime() -lt [DateTime]::Parse($Parent.start).ToUniversalTime()){throw 'Process creation ordering mismatch'}
 if($Pinned){foreach($key in @('pid','start','path','sid','sha256')){if($Parent.$key -cne $Pinned.parent.$key -or $Producer.$key -cne $Pinned.producer.$key){throw 'Pinned process identity changed/reused'}}}
}

function Get-ProbeCompleteRows([string]$Text) {
 $end=$Text.LastIndexOf("`n")
 if($end -lt 0){return}
 $Text.Substring(0,$end).Split("`n")|Where-Object {$_}|ForEach-Object {$_|ConvertFrom-Json}
}
function Get-ProbeLastCompleteRecord([string]$Text) {
 $end=$Text.LastIndexOf("`n")
 if($end -lt 0){return $null}
 $previous=if($end -gt 0){$Text.LastIndexOf("`n",$end-1)}else{-1}
 $line=$Text.Substring($previous+1,$end-$previous-1)
 if([string]::IsNullOrWhiteSpace($line)){return $null}
 return ($line|ConvertFrom-Json)
}
function Publish-PreparationOutcome([string]$Path,$Value) {
 $parent=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
 $temporary=Join-Path $parent ('p-'+[Guid]::NewGuid().ToString('N').Substring(0,16)+'.tmp')
 try{
  Publish-ProbeJson $temporary $Value
  if(Test-Path -LiteralPath $Path){[IO.File]::Replace($temporary,$Path,(Join-Path $parent ('b-'+[Guid]::NewGuid().ToString('N').Substring(0,16)+'.json')))}else{[IO.File]::Move($temporary,$Path)}
 }finally{if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary}}
}
function Resolve-ProbeControlRoot([string]$ScriptRoot,[string]$ControlPath,[string]$Nonce) {
 # The private run root name comes from admission and is bound by its own
 # run-identity.json (nonce, rootName); it is never re-derived from a template.
 if(!$ControlPath){throw 'ControlPath required'}
 if($Nonce -cnotmatch '^[a-f0-9]{64}$'){throw 'Nonce'}
 $full=[IO.Path]::GetFullPath($ControlPath).TrimEnd('\','/')
 if([IO.Path]::GetDirectoryName($full) -ine [IO.Path]::GetFullPath($ScriptRoot).TrimEnd('\','/')){throw 'ControlPath must be a private run root beside the driver'}
 $leaf=[IO.Path]::GetFileName($full)
 if($leaf -cnotmatch '^[A-Za-z0-9-]{1,80}$'){throw 'Private run root name'}
 if(!(Test-Path -LiteralPath $full -PathType Container)){throw 'Fresh capture ControlPath required'}
 $identityPath=Join-Path $full 'run-identity.json'
 if(!(Test-Path -LiteralPath $identityPath -PathType Leaf)){throw 'Private run identity missing'}
 $identity=[IO.File]::ReadAllText($identityPath)|ConvertFrom-Json
 if($identity.schema -cne 'fresh-admin-run-identity-v1' -or $identity.nonce -cne $Nonce -or $identity.rootName -cne $leaf){throw 'Private run identity binding'}
 return $full
}
