function Wait-DurationChild($Process,[int]$BoundMs,[int]$ObservationMs,[string]$Heartbeat) {
 $handle=$Process.Handle
 $identity=@{pid=$Process.Id;startFiletime=$Process.StartTime.ToFileTimeUtc();exe=$Process.MainModule.FileName}
 $clock=[Diagnostics.Stopwatch]::StartNew();$timedOut=$false
 while(!$Process.WaitForExit([Math]::Min(250,[Math]::Max(1,$BoundMs-[int]$clock.ElapsedMilliseconds)))){
  if($clock.ElapsedMilliseconds -ge $BoundMs){$timedOut=$true;break}
 }
 if($timedOut){
  $observe=[Diagnostics.Stopwatch]::StartNew()
  while(!$Process.HasExited -and $observe.ElapsedMilliseconds -lt $ObservationMs){
   $record=@{utc=[DateTime]::UtcNow.ToString('o');identity=$identity;timedOut=$true;alive=$true}|ConvertTo-Json -Compress
   $bytes=[Text.Encoding]::UTF8.GetBytes($record+"`n")
   $f=[IO.File]::Open($Heartbeat,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read)
   try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
   $null=$Process.WaitForExit([Math]::Min(1000,[Math]::Max(1,$ObservationMs-[int]$observe.ElapsedMilliseconds)))
  }
 }
 $exited=$Process.HasExited
 return [ordered]@{identity=$identity;timedOut=$timedOut;exited=$exited;exitCode=$(if($exited){$Process.ExitCode}else{$null});elapsedMs=$clock.ElapsedMilliseconds;restorePermitted=(!$timedOut -and $exited -and $Process.ExitCode -eq 0)}
}
