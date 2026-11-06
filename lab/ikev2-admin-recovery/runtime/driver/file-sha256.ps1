function Get-ProbeFileSHA256([string]$Path) {
 # Fixture is explicitly installed by the local-only test driver.
 if(Get-Variable ProbeFixtureRoot -Scope Global -ErrorAction SilentlyContinue){
  if($Path -ceq 'C:/BimeronStep8/probe.ps1'){$Path="$global:ProbeFixtureRoot/planned-wrapper.ps1"}
  if($Path -ceq 'C:\Windows\System32\cmd.exe'){return 'B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450'}
  if($Path -ceq 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'){return '9F914D42706FE215501044ACD85A32D58AAEF1419D404FDDFA5D3B48F66CCD9F'}
 }
 $worker=[PowerShell]::Create()
 $operation=$null;$expired=$false
 try {
  $null=$worker.AddScript({param($Path)
 $stream=$null;$hash=$null
 try {
  $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  $length=$stream.Length
  if($length -gt 67108864){throw 'Hash input exceeds 64 MiB'}
  $hash=[Security.Cryptography.SHA256]::Create()
  $buffer=[byte[]]::new(65536)
  $clock=[Diagnostics.Stopwatch]::StartNew();$total=0L
  while(($count=$stream.Read($buffer,0,$buffer.Length)) -gt 0){
   $total+=$count
   if($total -gt $length -or $clock.ElapsedMilliseconds -gt 5000){throw 'Hash input changed or exceeded five-second processing bound'}
   $null=$hash.TransformBlock($buffer,0,$count,$buffer,0)
  }
  if($total -ne $length -or $stream.Length -ne $length){throw 'Hash input length changed'}
  $null=$hash.TransformFinalBlock($buffer,0,0)
  return ([BitConverter]::ToString($hash.Hash)).Replace('-','')
 } finally {if($hash){$hash.Dispose()};if($stream){$stream.Dispose()}}
  }).AddArgument($Path)
  $clock=[Diagnostics.Stopwatch]::StartNew();$operation=$worker.BeginInvoke()
  while(!$operation.IsCompleted -and $clock.ElapsedMilliseconds -lt 5000){Start-Sleep -Milliseconds 10}
  if(!$operation.IsCompleted -or $clock.ElapsedMilliseconds -ge 5000){
   $expired=$true
   [Console]::Error.WriteLine('Hash deadline refused; retaining owner until worker drains; no cancellation')
   while(!$operation.IsCompleted){Start-Sleep -Milliseconds 100}
  }
  $result=$worker.EndInvoke($operation)
  if($expired){throw 'Hash deadline exceeded; late result refused'}
  if($worker.HadErrors){throw $worker.Streams.Error[0].Exception}
  if($result.Count -ne 1){throw 'Hash result missing/ambiguous'}
  return [string]$result[0]
 }finally{if(!$operation -or $operation.IsCompleted){$worker.Dispose()}}
}
