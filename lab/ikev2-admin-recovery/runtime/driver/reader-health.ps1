function Assert-HealthRecord($h,$now=[DateTime]::UtcNow) {
 $keys=if($h -is [Collections.IDictionary]){$h.Keys}else{$h.PSObject.Properties.Name}
 foreach($name in @('ready','healthy','utc','elapsed','completeBytes','failure')){
  if($null -eq $h -or $name -notin $keys){throw 'Producer health schema'}
 }
 if($h.ready -isnot [bool] -or $h.healthy -isnot [bool] -or $h.utc -isnot [string] -or $null -eq $h.elapsed -or $null -eq $h.completeBytes){throw 'Producer health schema'}
 foreach($v in @($h.elapsed,$h.completeBytes)){
  if($v -isnot [ValueType] -or $v -is [bool] -or [double]::IsNaN([double]$v) -or [double]::IsInfinity([double]$v) -or $v -lt 0){throw 'Producer health number'}
 }
 $age=($now-([DateTime]::Parse($h.utc).ToUniversalTime())).TotalSeconds
 if($age -lt 0 -or $age -gt 8){throw 'Producer readiness stale/future'}
 if($null -ne $h.failure -or (!$h.ready -and $h.healthy)){throw 'Producer readiness refused'}
}
function Assert-ReaderHealth($h,$pin,$nonce,$now=[DateTime]::UtcNow) {
 Assert-HealthRecord $h $now
 if($pin.nonce -cne $nonce -or !$pin.producer.pid){throw 'Producer pin mismatch'}
 if(!$h.ready -or !$h.healthy){throw 'Producer readiness refused'}
}
