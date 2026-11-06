param($journalCode,$healthCode,$nonce,$role,$controlCode)
$ErrorActionPreference='Stop'


if($nonce -cnotmatch '^[a-f0-9]{64}$' -or $role -cnotin @('supervisor','collector','barrier')){throw 'Reader binding'}
$root="C:/BimeronStep10Probe/$nonce/logs"

function Health {
 $text=[Text.UTF8Encoding]::new($false,$true).GetString([ProbeJournal]::Snapshot("$root/producer-health.jsonl"))
 $end=$text.LastIndexOf("`n");if($end -lt 0){throw 'Incomplete health'}
 $h=($text.Substring(0,$end).Trim().Split("`n")|Select-Object -Last 1)|ConvertFrom-Json
 Assert-ReaderHealth $h $pin $nonce
 return $h
}
$e=@{schema=1;nonce=$nonce;role=$role;readiness=$null;producer=$null;noHandle=$true;cancelled=$false;requestId=$null;samples=@();opened=$null;ready=$null;closed=$null;terminal=$null;completion=$null;completionObserved=$null;failure=$null}
$timer=[Diagnostics.Stopwatch]::StartNew();$journalInput=$null
function Observe-ReaderStop {
 $request=Read-ProbeStop "C:/BimeronStep10Probe/$nonce/stop-request.json" $nonce
 if($request){$e.cancelled=$true;$e.requestId=$request.requestId;return $true}
 return $false
}
function Publish-ReaderEvidence($kind){
 $path="$root/reader-$role-$kind.json";$pending=Join-Path $root ('.'+[Guid]::NewGuid().ToString('N').Substring(0,8)+'.tmp')
 [IO.File]::WriteAllText($pending,($e|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
 [IO.File]::Move($pending,$path)
}
try {
 . ([ScriptBlock]::Create($controlCode))
 if(Observe-ReaderStop){throw 'Reader cancelled before open'}
 Add-Type -TypeDefinition $journalCode
 . ([ScriptBlock]::Create($healthCode))
 $pin=[IO.File]::ReadAllText("$root/producer-pin.json")|ConvertFrom-Json
 $e.producer=$pin.producer;$e.readiness=Health
 $journalInput=[IO.FileStream]::new("$root/probe-$nonce.jsonl",[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
 $e.noHandle=$false;$e.opened=[DateTime]::UtcNow.ToString('o')
 while($timer.Elapsed.TotalSeconds -lt 1020 -and $e.samples.Count -lt 1100){
  if(Observe-ReaderStop){break}
  $before=[DateTime]::UtcNow.ToString('o');$mono=$timer.Elapsed.TotalSeconds
  $length=$journalInput.Length;if($length -gt 64MB){throw 'Snapshot bound'}
  $journalInput.Position=0;$bytes=New-Object byte[] ([int]$length);$offset=0
  while($offset -lt $length){$n=$journalInput.Read($bytes,$offset,$length-$offset);if(!$n){throw 'Journal truncated'};$offset+=$n}
  $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes);$end=$text.LastIndexOf("`n")
  if($end -lt 0){throw 'Incomplete journal'}
  $rows=$text.Substring(0,$end).Trim().Split("`n")
  $first=$rows[0]|ConvertFrom-Json;$last=$rows[-1]|ConvertFrom-Json
  foreach($row in @($first,$last)){
   if($row.nonce -cne $nonce -or $row.producer.pid -ne $pin.producer.pid -or $row.producer.sid -cne $pin.producer.sid -or $row.producer.start -cne $pin.producer.start){throw 'Journal producer mismatch'}
  }
  if($first.kind -cne 'start'){throw 'Missing producer start'}
  $after=[DateTime]::UtcNow.ToString('o');$done=$timer.Elapsed.TotalSeconds
  $e.samples+=@{before=$before;after=$after;mono=$mono;done=$done;bytes=$length}
  if(!$e.ready){$e.ready=$after;if($last.kind -eq 'end'){throw 'Terminal-only reader'};Publish-ReaderEvidence 'ready'}
  if($last.kind -eq 'end'){
   if($last.status -ceq 'cancelled'){if(!(Observe-ReaderStop) -or $last.requestId -cne $e.requestId){throw 'Unbound cancelled terminal'};break}
   if($last.target -cne 'all' -or $last.status -cne 'complete'){throw 'Invalid terminal'}
   $e.terminal=$last
   if(Test-Path "$root/inspector-final.json"){
    $final=[IO.File]::ReadAllText("$root/inspector-final.json")|ConvertFrom-Json
    if($final.completed -ne $true -or $final.failure -or $final.launch.nonce -cne $nonce -or @($final.processes).Count -ne 2 -or @($final.processes|Where-Object {$_.alive -ne $false}).Count){throw 'Producer completion refused'}
    $e.completion=$final;$e.completionObserved=[DateTime]::UtcNow.ToString('o');break
   }
  }
  if(!$e.terminal){$null=Health}
  for($slice=0;$slice -lt 4;$slice++){if(Observe-ReaderStop){break};Start-Sleep -Milliseconds 250}
 }
 if(!$e.completion -and !$e.cancelled){throw 'Reader deadline without completion'}
}catch{if(!$e.cancelled){$e.failure=$_.Exception.Message}}
finally{try{if($journalInput){$journalInput.Dispose()}}finally{$e.closed=[DateTime]::UtcNow.ToString('o');try{Publish-ReaderEvidence 'closed'}catch{$e.failure='Closure publication failed: '+$_.Exception.Message}}}
$e|ConvertTo-Json -Depth 8 -Compress
