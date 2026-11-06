# Full helper caller path with a local session surrogate; never opens PSDirect.
$ErrorActionPreference='Stop'
. "$PSScriptRoot/protected-guest.ps1"
$Nonce='a'*64
$testRoot=Join-Path $env:TEMP ('full300-helper-'+[guid]::NewGuid().ToString('N'))
$hostRoot=Join-Path $testRoot 'host';$guestRoot=Join-Path $testRoot 'guest'
foreach($r in @($hostRoot,$guestRoot)){foreach($d in @('','proofs','samples','commands','responses','transport','transport/proofs','transport/samples','transport/commands','transport/responses')){[IO.Directory]::CreateDirectory((Join-Path $r $d))|Out-Null}}
Copy-Item "$PSScriptRoot/owner-mailbox.ps1" "$guestRoot/owner-mailbox.ps1"
function Bytes($v){return ,([Text.Encoding]::UTF8.GetBytes(($v|ConvertTo-Json -Depth 16 -Compress)))}
function Proof($name,$value){$b=Bytes $value;Publish-OwnerBytesOnce "$hostRoot/proofs/$name" $b -Root $hostRoot;@{name=$name;length=$b.Length;sha256=(Get-OwnerSHA256 $b)}}
$config=Bytes @{nonce=$Nonce};Publish-OwnerBytesOnce "$hostRoot/config.json" $config -Root $hostRoot
$child=Proof 'readiness.json' @{ready=$true}
$admission=Proof 'admission.json' @{nonce=$Nonce}
$pins=Proof 'producer-pins.json' @(@{PID=1},@{PID=2})
$evidence=Proof 'admission-evidence.json' @{readiness=$child}
$command=Bytes @{schema='full300-owner-command-v1';nonce=$Nonce;configSHA256=(Get-OwnerSHA256 $config);seq=1;op='launch';body=@{admission=$admission;producerPins=$pins;admissionEvidence=$evidence}}
Publish-OwnerBytesOnce "$hostRoot/commands/00000001.json" $command -Root $hostRoot
$response=Bytes @{schema='full300-owner-response-v1';nonce=$Nonce;configSHA256=(Get-OwnerSHA256 $config);seq=1;commandSHA256=(Get-OwnerSHA256 $command);outcome='accepted';state='OWNING';owner=$null;refs=@();error=$null}
Publish-OwnerBytesOnce "$guestRoot/transport/responses/00000001.json" $response -Root $guestRoot
function Invoke-Command {param($Session,$Root,$Path,$ScriptBlock,$ArgumentList) & $ScriptBlock @ArgumentList}
$return=Submit-OwnerCommand 'fake' $guestRoot "$hostRoot/commands/00000001.json"
if((Get-OwnerSHA256 ([Text.Encoding]::UTF8.GetBytes($return))) -cne (Get-OwnerSHA256 $response)){throw 'Exact response bytes lost'}
if(!(Test-Path "$guestRoot/transport/proofs/readiness.json")){throw 'Transitive proof omitted'}
$again=Fetch-OwnerResponse 'fake' $guestRoot "$hostRoot/commands/00000001.json"
if($again -cne $return){throw 'Reconciliation changed response'}
# A changed nested proof must prevent publication of the command.
[IO.File]::WriteAllText("$hostRoot/proofs/readiness.json",'{}')
$refused=$false
try{Submit-OwnerCommand 'fake' $guestRoot "$hostRoot/commands/00000001.json"|Out-Null}catch{$refused=$true}
if(!$refused){throw 'Changed nested proof accepted'}
'Offline actual Submit/Fetch helper and transitive proof tests passed'
# Keep temporary evidence for review; no broad cleanup commands.
