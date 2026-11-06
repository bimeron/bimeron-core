# Parent-mediated presence: one fresh immutable request, no fabricated response.
function Wait-StockHuman($Root,$Binding,[string]$GuardHash,[string]$LauncherHash,[string]$ReviewHash) {
 $random=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
 try{$rng.GetBytes($random)}finally{$rng.Dispose()}
 $challenge=([BitConverter]::ToString($random)).Replace('-','').ToLowerInvariant()
 $request=@{schema='stock-human-request-v1';nonce=$Binding.Nonce;binding=$Binding;guardSHA256=$GuardHash;launcherSHA256=$LauncherHash;reviewSHA256=$ReviewHash;generatedUtc=[DateTime]::UtcNow.ToString('o');challenge=$challenge}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($request|ConvertTo-Json -Depth 12 -Compress))
 Write-StockOnce "$Root/stock-human-request.json" $bytes
 $hash=Get-StockHash $bytes;$clock=[Diagnostics.Stopwatch]::StartNew()
 while(!(Test-Path -LiteralPath "$Root/stock-human-ready.json")){
  if($clock.Elapsed.TotalSeconds -ge 120){return $null}
  Start-Sleep -Milliseconds 100
 }
 $r=Assert-StrictOwnerJson ([IO.File]::ReadAllBytes("$Root/stock-human-ready.json"))
 Assert-OwnerFields $r @('schema','nonce','binding','requestSHA256','challenge','launcherSHA256','reviewSHA256','sourceThreadId','sourceResponseId','responseUtc','issuedUtc','expiresUtc','observingExistingDesktop','provenance')
 if($r.schema -cne 'stock-human-ready-v1' -or $r.nonce -cne $Binding.Nonce -or $r.requestSHA256 -cne $hash -or $r.challenge -cne $challenge -or $r.launcherSHA256 -cne $LauncherHash -or $r.reviewSHA256 -cne $ReviewHash -or $r.observingExistingDesktop -isnot [bool] -or !$r.observingExistingDesktop -or !$r.sourceThreadId -or !$r.sourceResponseId){throw 'Human attestation binding'}
 foreach($k in @('SHA256','Nonce','PolicySHA256')){if($r.binding.$k -cne $Binding.$k){throw 'Human binding'}}
 Assert-OwnerFields $r.provenance @('name','sha256','length')
 if($r.provenance.name -cne 'stock-human-provenance.json'){throw 'Human provenance name'}
 $raw=[IO.File]::ReadAllBytes("$Root/stock-human-provenance.json")
 if($raw.Length -ne $r.provenance.length -or (Get-StockHash $raw) -cne $r.provenance.sha256){throw 'Human provenance bytes'}
 $p=Assert-StrictOwnerJson $raw
 Assert-OwnerFields $p @('schema','sourceThreadId','sourceResponseId','responseUtc','role','text','stage')
 if($p.schema -cne 'stock-human-provenance-v1' -or $p.role -cne 'user' -or $p.stage -cne 'single-stock-ui' -or !$p.text -or $p.sourceThreadId -cne $r.sourceThreadId -or $p.sourceResponseId -cne $r.sourceResponseId -or $p.responseUtc -cne $r.responseUtc){throw 'Human source provenance'}
 $now=[DateTimeOffset]::UtcNow;$issued=[DateTimeOffset]::Parse($r.issuedUtc);$expiry=[DateTimeOffset]::Parse($r.expiresUtc);$response=[DateTimeOffset]::Parse($r.responseUtc);$generated=[DateTimeOffset]::Parse($request.generatedUtc)
 if($issued -lt $generated -or $issued -gt $now -or $response -gt $issued -or ($now-$response).TotalMinutes -gt 30 -or ($expiry-$issued).TotalSeconds -ne 120 -or $expiry -le $now){throw 'Human timing'}
 if(Test-Path -LiteralPath "$Root/stock-human-revoked.json"){throw 'Human presence revoked'}
 return $r
}
function Assert-StockHumanCurrent($Root,$Ready) {
 if($null -eq $Ready -or [DateTimeOffset]::UtcNow -ge [DateTimeOffset]::Parse($Ready.expiresUtc) -or ([DateTimeOffset]::UtcNow-[DateTimeOffset]::Parse($Ready.responseUtc)).TotalMinutes -gt 30 -or (Test-Path -LiteralPath "$Root/stock-human-revoked.json")){throw 'Human presence expired/revoked'}
}
