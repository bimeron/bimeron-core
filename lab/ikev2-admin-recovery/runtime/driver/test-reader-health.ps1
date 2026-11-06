$ErrorActionPreference='Stop'
. "$PSScriptRoot/reader-health.ps1"
$nonce='a'*64;$pin=@{nonce=$nonce;producer=@{pid=1}};$now=[DateTime]::UtcNow
foreach($age in @(0,1,8,9,-1)){
 $h=@{utc=$now.AddSeconds(-$age).ToString('o');elapsed=1;completeBytes=10;ready=$true;healthy=$true;failure=$null}
 $failed=$false;try{Assert-ReaderHealth $h $pin $nonce $now}catch{$failed=$true}
 if($failed -ne ($age -lt 0 -or $age -gt 8)){throw "Age classification $age"}
}
foreach($case in @('nonce','bool','number','missing','failure')){
 $h=@{utc=$now.ToString('o');elapsed=1;completeBytes=10;ready=$true;healthy=$true;failure=$null};$n=$nonce
 switch($case){nonce{$n='b'*64} bool{$h.ready='true'} number{$h.elapsed='1'} missing{$h.Remove('completeBytes')} failure{$h.failure='sticky'}}
 $failed=$false;try{Assert-ReaderHealth $h $pin $n $now}catch{$failed=$true};if(!$failed){throw "Accepted invalid $case"}
}
foreach($name in @('guest-read.ps1','persistent-reader.ps1','reader-health.ps1')){
 $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($errors|Out-String)}
}
'PASS health fresh/stale/future/schema/nonce and changed PowerShell parsers; no native calls'
