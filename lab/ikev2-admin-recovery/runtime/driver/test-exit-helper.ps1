# Actual exit submission and fetch paths; only the PSDirect boundary is mocked.
$ErrorActionPreference='Stop'
. "$PSScriptRoot/protected-guest.ps1"
$Nonce='a'*64
$testRoot=Join-Path $PSScriptRoot ('exit-helper-tests/'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($testRoot)|Out-Null
function Bytes($v){return ,([Text.UTF8Encoding]::new($false).GetBytes(($v|ConvertTo-Json -Depth 16 -Compress)))}
function Ref($name,[byte[]]$bytes){@{name=$name;length=$bytes.Length;sha256=(Get-OwnerSHA256 $bytes)}}
$script:remoteCalls=0
function Invoke-Command {
 param($Session,[scriptblock]$ScriptBlock,[object[]]$ArgumentList)
 $script:remoteCalls++
 & $ScriptBlock @ArgumentList
}
function Check($condition,$message){if(!$condition){throw $message}}
foreach($scenario in @('valid','host-hash','host-length','wrong-host-namespace','guest-conflict')){
 $caseRoot=Join-Path $testRoot $scenario
 $hostRoot=Join-Path $caseRoot 'host';$guestRoot=Join-Path $caseRoot 'guest'
 foreach($d in @('proofs','samples','commands','responses')){
  [IO.Directory]::CreateDirectory("$hostRoot/$d")|Out-Null
  [IO.Directory]::CreateDirectory("$guestRoot/transport/$d")|Out-Null
 }
 Copy-Item "$PSScriptRoot/owner-mailbox.ps1" "$guestRoot/owner-mailbox.ps1"
 $cfg=Bytes @{nonce=$Nonce;taskName="BimeronFull300Owner-$Nonce"}
 Publish-OwnerBytesOnce "$hostRoot/config.json" $cfg -Root $hostRoot
 $cfgHash=Get-OwnerSHA256 $cfg
 $status=Bytes @{State='Completed300';Nonce=$Nonce}
 # Two complete JSONL records ensure the resolver never treats JSONL as one JSON value.
 $events=[Text.Encoding]::UTF8.GetBytes("{`"Event`":`"cleanup`"}`n{`"Event`":`"exit`"}`n")
 $statusRef=Ref '7-gate-status.json' $status;$eventsRef=Ref '7-events.jsonl' $events
 $exit=Bytes @{schema='full300-owner-exit-v1';nonce=$Nonce;configSHA256=$cfgHash;supervisorOnceSHA256=('b'*64);launchIntentSHA256=('c'*64);owner=@{pid=123;creationFileTime='123456';path='fixture/full300-owner.exe';sha256=('d'*64)};waitResult='signalled';exitCode=0;exitUtc='2026-11-04T00:00:00.0000000Z';cleanupRequestSHA256=('e'*64);nativeStatus=$statusRef;nativeEvents=$eventsRef}
 $exitRef=Ref 'owner-exit.json' $exit
 Publish-OwnerBytesOnce "$hostRoot/proofs/owner-exit.json" $exit -Root $hostRoot
 foreach($pair in @(@($statusRef,$status),@($eventsRef,$events))){
  $dir=if($scenario -eq 'wrong-host-namespace'){'proofs'}else{'samples'}
  Publish-OwnerBytesOnce "$hostRoot/$dir/$($pair[0].name)" $pair[1] -Root $hostRoot
 }
 # Supervisor-owned files already exist at the guest; exact replay must be harmless.
 Publish-OwnerBytesOnce "$guestRoot/transport/proofs/owner-exit.json" $exit -Root $guestRoot
 Publish-OwnerBytesOnce "$guestRoot/transport/samples/7-gate-status.json" $status -Root $guestRoot
 Publish-OwnerBytesOnce "$guestRoot/transport/samples/7-events.jsonl" $events -Root $guestRoot
 if($scenario -eq 'host-hash'){
  $changed=[byte[]]$status.Clone();$changed[0]=32
  [IO.File]::WriteAllBytes("$hostRoot/samples/7-gate-status.json",$changed)
  # Correct bytes in the wrong namespace must not mask a corrupt sample.
  Publish-OwnerBytesOnce "$hostRoot/proofs/7-gate-status.json" $status -Root $hostRoot
 }
 if($scenario -eq 'host-length'){[IO.File]::WriteAllBytes("$hostRoot/samples/7-events.jsonl",[byte[]]@(10))}
 if($scenario -eq 'guest-conflict'){[IO.File]::WriteAllBytes("$guestRoot/transport/samples/7-gate-status.json",[byte[]]@(32))}
 $command=Bytes @{schema='full300-owner-command-v1';nonce=$Nonce;configSHA256=$cfgHash;seq=8;op='exit-supervisor';body=@{ownerExit=$exitRef}}
 $path="$hostRoot/commands/00000008.json"
 Publish-OwnerBytesOnce $path $command -Root $hostRoot
 $response=Bytes @{schema='full300-owner-response-v1';nonce=$Nonce;configSHA256=$cfgHash;seq=8;commandSHA256=(Get-OwnerSHA256 $command);outcome='accepted';state='EXIT_READY';owner=$null;refs=@($exitRef,$statusRef,$eventsRef);error=$null}
 Publish-OwnerBytesOnce "$guestRoot/transport/responses/00000008.json" $response -Root $guestRoot
 $before=$script:remoteCalls;$failure=$null
 try{$result=Submit-OwnerCommand 'local-only' $guestRoot $path}catch{$failure=$_}
 if($scenario -eq 'valid'){
  if($failure){throw $failure}
  Check ($result -ceq [Text.Encoding]::UTF8.GetString($response)) 'Response bytes changed'
  Check ((Get-OwnerSHA256 (Read-OwnerBytes "$guestRoot/transport/commands/00000008.json" -Root $guestRoot)) -ceq (Get-OwnerSHA256 $command)) 'Command bytes changed'
  foreach($pair in @(@($statusRef,$status),@($eventsRef,$events))){
   Check ((Get-OwnerSHA256 (Read-OwnerBytes "$guestRoot/transport/samples/$($pair[0].name)" -Root $guestRoot)) -ceq $pair[0].sha256) 'Namespaced sample changed'
   Check (!(Test-Path "$guestRoot/transport/proofs/$($pair[0].name)")) 'Sample silently copied into proofs'
  }
  Check ((Fetch-OwnerResponse 'local-only' $guestRoot $path) -ceq $result) 'Fetch reconciliation changed bytes'
  # Exercise the real final helper through ready retrieval and binding rejection.
  # Never reach its scheduler observation/deletion boundary in this offline test.
  $ready=Bytes @{schema='full300-supervisor-exit-v1';nonce=$Nonce;configSHA256=$cfgHash;supervisorOnceSHA256=('b'*64);exitCommandSHA256=('f'*64);proofSHA256=$exitRef.sha256;reason='owner-signalled'}
  Publish-OwnerBytesOnce "$guestRoot/transport/proofs/supervisor-exit-ready.json" $ready -Root $guestRoot
  $beforeFinal=$script:remoteCalls;$finalFailure=$null
  try{Complete-OwnerFinal 'local-only' $guestRoot $path}catch{$finalFailure=$_}
  Check ($null -ne $finalFailure -and "$finalFailure" -match 'HOLD: exit-ready binding mismatch') "Final helper readiness result: $finalFailure"
  Check ($script:remoteCalls -eq $beforeFinal+1) 'Final helper reached scheduler boundary'
  Check (!(Test-Path "$hostRoot/task-final.json")) 'Final helper archived invalid closure'
 }else{
  Check ($null -ne $failure) "Accepted mismatch: $scenario"
  Check (!(Test-Path "$guestRoot/transport/commands/00000008.json")) "Published command on mismatch: $scenario"
  if($scenario -in @('host-hash','host-length')){Check ("$failure" -match 'Transitive proof mismatch') 'Wrong mismatch failure'}
  if($scenario -ne 'guest-conflict'){Check ($script:remoteCalls -eq $before) 'Host mismatch reached remote boundary'}
  else{Check ("$failure" -match 'Immutable publication conflict') 'Guest mismatch not detected'}
 }
 "PASS: exit helper $scenario"
}
foreach($name in @('0-gate-status.json','01-gate-status.json','7-unknown.json','7-Gate-status.json','../7-events.jsonl','7-events.jsonl/extra')){
 $failed=$false;try{$null=Get-OwnerReferenceNamespace $name}catch{$failed=$true}
 Check $failed "Namespace accepted $name"
}
'PASS: exact namespace allowlist and final binding rejection'
"Evidence retained: $testRoot"


