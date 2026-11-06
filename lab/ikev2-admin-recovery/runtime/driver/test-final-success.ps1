# Offline: execute the actual final dispatcher with a fake scheduler only.
$ErrorActionPreference='Stop'
. "$PSScriptRoot/protected-guest.ps1"
$Nonce='d'*64
$testRoot=Join-Path $PSScriptRoot ('offline-final-'+[guid]::NewGuid().ToString('N'))
$hostRoot=Join-Path $testRoot 'host';$guestRoot=Join-Path $testRoot 'guest'
foreach($path in @($hostRoot,"$hostRoot/commands","$hostRoot/proofs",$guestRoot,"$guestRoot/transport","$guestRoot/transport/proofs")){[IO.Directory]::CreateDirectory($path)|Out-Null}
[IO.File]::Copy("$PSScriptRoot/owner-mailbox.ps1","$guestRoot/owner-mailbox.ps1")
function Bytes($value){return ,([Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 16 -Compress)))}
$cfg=Bytes @{nonce=$Nonce;taskName="BimeronFull300Owner-$Nonce"}
$cfgHash=Get-OwnerSHA256 $cfg
$proof=Bytes @{schema='full300-no-launch-v1';nonce=$Nonce;configSHA256=$cfgHash;supervisorOnceSHA256=('b'*64);sealed=$true;launchAttempted=$false;sealCommandSHA256=('c'*64)}
$ref=@{name='no-launch.json';sha256=(Get-OwnerSHA256 $proof);length=$proof.Length}
$cmd=Bytes @{schema='full300-owner-command-v1';nonce=$Nonce;configSHA256=$cfgHash;seq=2;op='exit-supervisor';body=@{noLaunch=$ref}}
$ready=Bytes @{schema='full300-supervisor-exit-v1';nonce=$Nonce;configSHA256=$cfgHash;supervisorOnceSHA256=('b'*64);exitCommandSHA256=(Get-OwnerSHA256 $cmd);proofSHA256=$ref.sha256;reason='sealed-no-launch'}
$instance=[guid]::NewGuid().ToString()
Publish-OwnerBytesOnce "$hostRoot/config.json" $cfg -Root $hostRoot
Publish-OwnerBytesOnce "$hostRoot/commands/00000002.json" $cmd -Root $hostRoot
Publish-OwnerBytesOnce "$hostRoot/proofs/no-launch.json" $proof -Root $hostRoot
Publish-OwnerBytesOnce "$hostRoot/task-registration.json" (Bytes @{xml='fixture-xml';sddl='fixture-acl';fileSddl='fixture-file-acl'}) -Root $hostRoot
Publish-OwnerBytesOnce "$hostRoot/task-instance.json" (Bytes @{instanceGuid=$instance}) -Root $hostRoot
Publish-OwnerBytesOnce "$guestRoot/transport/proofs/supervisor-exit-ready.json" $ready -Root $guestRoot
$script:deleted=$false;$script:observed=0
$script:fakeTask=[pscustomobject]@{Name="BimeronFull300Owner-$Nonce";Xml='fixture-xml';State=3;LastTaskResult=0}
$script:fakeTask|Add-Member ScriptMethod GetSecurityDescriptor {param($flags)'fixture-acl'}
$script:fakeTask|Add-Member ScriptMethod GetInstances {param($flags)$script:observed++;return @()}
$script:fakeFolder=[pscustomobject]@{}
$script:fakeFolder|Add-Member ScriptMethod GetTask {param($name)if($name -cne "BimeronFull300Owner-$Nonce"){throw 'Wrong task'};return $script:fakeTask}
$script:fakeFolder|Add-Member ScriptMethod DeleteTask {param($name,$flags)
 if($name -cne "BimeronFull300Owner-$Nonce" -or $script:observed -lt 2){throw 'Deletion without fresh observation'}
 if(!(Test-Path "$hostRoot/task-final.json") -or !(Test-Path "$hostRoot/proofs/supervisor-exit-ready.json")){throw 'Deletion before archival'}
 $script:deleted=$true
}
$script:fakeService=[pscustomobject]@{}
$script:fakeService|Add-Member ScriptMethod Connect {}
$script:fakeService|Add-Member ScriptMethod GetFolder {param($path)if($path -cne '\'){throw 'Wrong folder'};return $script:fakeFolder}
function New-Object {
 [CmdletBinding(DefaultParameterSetName='Net')]
 param([Parameter(ParameterSetName='Com',Mandatory=$true)][string]$ComObject,
       [Parameter(ParameterSetName='Net',Mandatory=$true,Position=0)][string]$TypeName,
       [Parameter(ParameterSetName='Net',Position=1)][object[]]$ArgumentList)
 if($PSCmdlet.ParameterSetName -eq 'Com'){
  if($ComObject -cne 'Schedule.Service'){throw 'Unexpected COM construction'}
  return $script:fakeService
 }
 Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}
function Invoke-Command {param($Session,[scriptblock]$ScriptBlock,[object[]]$ArgumentList)& $ScriptBlock @ArgumentList}
function Get-Acl {param($LiteralPath,$ErrorAction)
 if([IO.Path]::GetFileName($LiteralPath) -cne "BimeronFull300Owner-$Nonce"){throw 'Wrong task ACL path'}
 $script:aclReads++
 $acl=[pscustomobject]@{};$acl|Add-Member ScriptMethod GetSecurityDescriptorSddlForm {param($sections)'fixture-file-acl'};$acl
}
$script:aclReads=0
Complete-OwnerFinal 'offline-only' $guestRoot "$hostRoot/commands/00000002.json"
if(!$script:deleted){throw 'Owned task not unregistered'}
$final=Assert-StrictOwnerJson (Read-OwnerBytes "$hostRoot/task-final.json" -Root $hostRoot)
if($final.instanceGuid -cne $instance -or $final.state -ne 3 -or @($final.instanceGuids).Count){throw 'Final evidence mismatch'}
if($final.fileSddl -cne 'fixture-file-acl' -or $script:aclReads -lt 2){throw 'Final ACL evidence or deletion recheck missing'}
'PASS: actual final dispatcher archives exact closure then rechecks and unregisters'
"Evidence retained: $testRoot"
