param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Path $Output -ErrorAction Stop | Out-Null
$Output=(Resolve-Path -LiteralPath $Output).Path
Add-Type -Path "$PSScriptRoot/Journal.cs"
$log=Join-Path $Output 'concurrent.jsonl'
$writer=[ProbeJournal]::new($log)
$jobs=@();$results=@()
try{
 foreach($reader in 1..3){
  $jobs+=Start-Job -ScriptBlock {
   param($code,$log,$output,$reader)
   $ErrorActionPreference='Stop';Add-Type -Path $code
   for($i=0;$i -lt 150;$i++){
    $b=[ProbeJournal]::Snapshot($log)
    if($reader -eq 3){$p=Join-Path $output "closed-$i.bin";[IO.File]::WriteAllBytes($p,$b);Copy-Item -LiteralPath $p -Destination "$p.copy"}
    Start-Sleep -Milliseconds 10
   }
   "reader-$reader-ok"
  } -ArgumentList "$PSScriptRoot/Journal.cs",$log,$Output,$reader
 }
 for($i=1;$i -le 500;$i++){$writer.Record('{"sequence":'+$i+'}');Start-Sleep -Milliseconds 5}
 foreach($j in $jobs){if(!(Wait-Job $j -Timeout 15)){throw 'Reader timeout'};$results+=Receive-Job $j -ErrorAction Stop;if($j.State -ne 'Completed'){throw 'Reader failed'}}
 # A reader that denies writer sharing cannot coexist with the lifetime writer.
 $refused=$false
 try{$h=[IO.File]::Open($log,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$h.Dispose()}catch [IO.IOException]{$refused=$true}
 if(!$refused){throw 'Incompatible reader was accepted'}
 $writer.Record('{"sequence":501}')
}finally{$writer.Dispose();foreach($j in $jobs){Remove-Job $j -Force}}
# Controlled old mechanism: opening for append is rejected while a reader denies write sharing.
$old=Join-Path $Output 'old.jsonl';[IO.File]::WriteAllText($old,'')
$reader=[IO.File]::Open($old,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$oldFailed=$false
try{try{Add-Content -LiteralPath $old -Value 'record' -ErrorAction Stop}catch{$oldFailed=$true;$_.Exception.GetType().FullName | Set-Content (Join-Path $Output 'old-error.txt')}}finally{$reader.Dispose()}
if(!$oldFailed){throw 'Old sharing conflict not reproduced'}
$missing=$false;try{[ProbeJournal]::Snapshot((Join-Path $Output 'missing'))|Out-Null}catch{$missing=$true}
if(!$missing){throw 'Missing reader source accepted'}
@{readers=$results;records=501;incompatibleReaderRefused=$refused;oldAddContentFailed=$oldFailed;missingSourceRefused=$missing;historicalAttribution='unknown'}|ConvertTo-Json|Set-Content (Join-Path $Output 'result.json')
