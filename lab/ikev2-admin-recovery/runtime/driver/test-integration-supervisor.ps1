# Offline supervisor initialization/snapshot lifecycle using fake identity and scheduler.
$ErrorActionPreference='Stop'
. "$PSScriptRoot/owner-mailbox.ps1"
. "$PSScriptRoot/owner-supervisor.ps1"
. "$PSScriptRoot/owner-bindings.ps1"
$script:nonce='b'*64
$script:root=Join-Path $env:TEMP ('full300-supervisor-'+[guid]::NewGuid().ToString('N'))
foreach($d in @('','transport','transport/proofs','transport/samples','transport/responses')){[IO.Directory]::CreateDirectory((Join-Path $script:root $d))|Out-Null}
function Get-OwnerInstanceFacts {@{principalSid='S-1-5-21-1-2-3-1001';elevated=$true;sessionId=2;pid=99;creationFileTime='123'}}
$definition=[pscustomobject]@{Principal=[pscustomobject]@{UserId='S-1-5-21-1-2-3-1001';RunLevel=1;LogonType=3};Triggers=@();Actions=@('fake');Settings=[pscustomobject]@{RestartCount=0;ExecutionTimeLimit='PT0S';AllowHardTerminate=$false}}
$script:task=[pscustomobject]@{Xml='fixture';Definition=$definition}
$script:task|Add-Member ScriptMethod GetSecurityDescriptor {param($flags)'fixture-acl'}
function Get-OwnerRegisteredTask($Name){$script:task}
function Get-Acl {param($LiteralPath,$ErrorAction)
 if([IO.Path]::GetFileName($LiteralPath) -cne "BimeronFull300Owner-$script:nonce"){throw 'Wrong task ACL path'}
 $script:aclReads++
 $acl=[pscustomobject]@{};$acl|Add-Member ScriptMethod GetSecurityDescriptorSddlForm {param($sections)'fixture-file-acl'};$acl
}
$script:aclReads=0
$ledger=@()
foreach($name in @('full300-owner.exe','owner-supervisor.ps1')){
 # Deliberately not executable fixture bytes; no process launch in this test.
 $bytes=[Text.Encoding]::UTF8.GetBytes($name)
 Publish-OwnerBytesOnce "$script:root/$name" $bytes -Root $script:root
 $ledger+=@{name=$name;sha256=(Get-OwnerSHA256 $bytes);length=$bytes.Length}
}
$lb=ConvertTo-OwnerBytes @{files=$ledger}
Publish-OwnerBytesOnce "$script:root/deployment.json" $lb -Root $script:root
$script:config=Assert-StrictOwnerJson (ConvertTo-OwnerBytes @{schema='full300-owner-config-v1';nonce=$script:nonce;vm='<LAB_VM_ID>';guest=$env:COMPUTERNAME;principalName='test';principalSid='S-1-5-21-1-2-3-1001';taskName="BimeronFull300Owner-$script:nonce";ownerSHA256=$ledger[0].sha256;supervisorSHA256=$ledger[1].sha256;ledgerSHA256=(Get-OwnerSHA256 $lb)})
Publish-OwnerBytesOnce "$script:root/transport/task-registration.json" (ConvertTo-OwnerBytes @{xml='fixture';sddl='fixture-acl'}) -Root $script:root
$refused=$false
try{Initialize-OwnerInstance $script:root $script:config ('c'*64)|Out-Null}catch{if($_ -notmatch 'task file ACL'){throw};$refused=$true}
if(!$refused -or (Test-Path "$script:root/transport/proofs/supervisor-once.json")){throw 'Missing file ACL baseline admitted supervisor'}
# Replace only offline test input after the refusal; production publication stays immutable.
[IO.File]::WriteAllBytes("$script:root/transport/task-registration.json",(ConvertTo-OwnerBytes @{xml='fixture';sddl='fixture-acl';fileSddl='fixture-file-acl'}))
$once=Initialize-OwnerInstance $script:root $script:config ('c'*64)
if($script:aclReads -ne 1){throw 'Supervisor did not read actual task file ACL'}
if($once -cnotmatch '^[a-f0-9]{64}$'){throw 'Missing original instance hash'}
$refused=$false;try{Initialize-OwnerInstance $script:root $script:config ('c'*64)|Out-Null}catch{$refused=$true}
if(!$refused){throw 'Second supervisor adopted original instance'}
Publish-OwnerBytesOnce "$script:root/events.jsonl" ([Text.Encoding]::UTF8.GetBytes("{`"Event`":`"bootstrap HOLD`"}`npartial")) -Root $script:root
$snapshot=Save-OwnerNativeSnapshots $script:root 1 $once
$raw=Read-OwnerBytes "$script:root/transport/samples/1-events.jsonl" -Root $script:root
if($raw[-1] -ne 10 -or [Text.Encoding]::UTF8.GetString($raw).Contains('partial')){throw 'Partial event published'}
'Offline initialization, original-instance refusal and native snapshot tests passed'
