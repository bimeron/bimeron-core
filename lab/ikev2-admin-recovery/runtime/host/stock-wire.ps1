# Exact launcher v2 wire parser/serializer. No native calls.
function Read-StockWire([byte[]]$Bytes,[string[]]$Keys) {
 $utf8=[Text.UTF8Encoding]::new($false,$true)
 $text=$utf8.GetString($Bytes)
 if($text.Contains("`r") -or $text.EndsWith("`n") -or $text.StartsWith([string][char]0xfeff,[StringComparison]::Ordinal)){throw 'Wire encoding'}
 $lines=$text.Split("`n")
 if($lines.Count -ne $Keys.Count){throw 'Wire count'}
 $value=[ordered]@{}
 for($i=0;$i -lt $Keys.Count;$i++){
  $prefix=$Keys[$i]+'='
  if(!$lines[$i].StartsWith($prefix,[StringComparison]::Ordinal)){throw 'Wire order'}
  $v=$lines[$i].Substring($prefix.Length)
  if(!$v -or $v.Contains('=') -or $v.Contains([string][char]0)){throw 'Wire value'}
  $value[$Keys[$i]]=$v
 }
 return $value
}
function ConvertTo-StockWire($Value) {
 $lines=@($Value.Keys | ForEach-Object {
  $v=[string]$Value[$_]
  if(!$v -or $v.Contains("`n") -or $v.Contains("`r") -or $v.Contains('=') -or $v.Contains([string][char]0)){throw 'Wire value'}
  $_+'='+$v
 })
 return ,([Text.UTF8Encoding]::new($false,$true).GetBytes(($lines -join "`n")))
}
function Assert-StockDecimal([string]$Value,[uint64]$Maximum) {
 if($Value -cnotmatch '^(0|[1-9][0-9]*)$'){throw 'Noncanonical decimal'}
 $n=[uint64]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture)
 if($n -gt $Maximum){throw 'Decimal range'}
}
function Assert-StockReadiness($R,$C,[string]$ConfigHash,$Pin) {
 if($R.version -cne '2' -or $R.nonce -cne $C.nonce -or $R.configSHA256 -cne $ConfigHash -or $R.executableSHA256 -cne $C.executableSHA256){throw 'Readiness binding'}
 foreach($k in @('elevation','phonebookMatches','profileAccepted')){if($R[$k] -cne '1'){throw 'Readiness predicate'}}
 if($R.SID -cne $C.expectedSid -or $R.session -cne '2' -or $R.logonHigh -cne $C.expectedLogonHigh -or $R.logonLow -cne $C.expectedLogonLow){throw 'Readiness context'}
 foreach($k in @('pid','session','logonHigh','logonLow')){Assert-StockDecimal $R[$k] ([uint32]::MaxValue)}
 Assert-StockDecimal $R.creationFileTime ([long]::MaxValue)
 if(!$Pin.Alive -or [string]$Pin.Pid -cne $R.pid -or [string]$Pin.CreationFileTime -cne $R.creationFileTime -or $Pin.Sid -cne $R.SID -or [string]$Pin.Session -cne $R.session -or [string]$Pin.LogonHigh -cne $R.logonHigh -or [string]$Pin.LogonLow -cne $R.logonLow -or !$Pin.Elevated){throw 'Retained process mismatch'}
}
function New-StockPermit($C,$R,[string]$ConfigHash,[string]$ReadinessHash,[long]$NowTicks) {
 foreach($h in @($C.nonce,$ConfigHash,$ReadinessHash,$C.executableSHA256,$C.reviewSHA256)){if($h -cnotmatch '^[a-f0-9]{64}$'){throw 'Permit digest'}}
 return ConvertTo-StockWire ([ordered]@{version='2';nonce=$C.nonce;configSHA256=$ConfigHash;readinessSHA256=$ReadinessHash;executableSHA256=$C.executableSHA256;reviewSHA256=$C.reviewSHA256;pid=$R.pid;creationFileTime=$R.creationFileTime;expiresUtcTicks=($NowTicks+[TimeSpan]::FromSeconds(25).Ticks).ToString([Globalization.CultureInfo]::InvariantCulture)})
}
