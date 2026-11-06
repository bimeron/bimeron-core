$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot 'protected-guest.ps1'
$tokens=$null;$errors=$null
$null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
function New-PSSession {throw 'Forbidden live session in offline test'}
function Invoke-Command {throw 'Forbidden remote execution in offline test'}
. $path
foreach($name in @('Open-OwnerSession','Install-OwnerTask','Submit-OwnerCommand','Fetch-OwnerResponse','Reconcile-OwnerLaunch')){if(!(Get-Command $name -CommandType Function)){throw "Missing $name"}}
function Fetch-OwnerResponse($Session,$Root,$Path){if($Session -ne 'fake' -or $Path -ne 'command'){throw 'Argument binding'};'frozen response'}
if((Reconcile-OwnerLaunch 'fake' 'root' 'command') -cne 'frozen response'){throw 'Reconcile must fetch only'}
'Offline syntax/import/reconciliation tests passed'
$p=Join-Path $PSScriptRoot 'protected-guest.ps1'
. $p
$fake=[pscustomobject]@{Name='OfflineTask';Xml='<Task/>';State=3;LastTaskResult=0;Instances=@();Descriptor='baseline'}
$fake|Add-Member ScriptMethod GetSecurityDescriptor {param($flags)$this.Descriptor}
$fake|Add-Member ScriptMethod GetInstances {param($flags)$this.Instances}
$baseline=Get-OwnerTaskRegistration $fake
$baseline.fileSddl='fixture-file-acl'
$script:fileSddl='fixture-file-acl'
function Get-Acl {param($LiteralPath,$ErrorAction)
 if([IO.Path]::GetFileName($LiteralPath) -cne 'OfflineTask'){throw 'Wrong task ACL path'}
 $acl=[pscustomobject]@{Value=$script:fileSddl};$acl|Add-Member ScriptMethod GetSecurityDescriptorSddlForm {param($sections)$this.Value};$acl
}
$id='11111111-1111-1111-1111-111111111111'
$proof=Wait-OwnerTaskExit $fake $baseline $id 1 {throw 'Unexpected wait'}
if($proof.instanceGuid -cne $id -or $proof.state -ne 3){throw 'Exit proof mismatch'}
foreach($invalid in @($null,'','changed')){
 $bad=@{xml=$baseline.xml;sddl=$baseline.sddl}
 if($null -ne $invalid){$bad.fileSddl=$invalid}
 $refused=$false
 try{Wait-OwnerTaskExit $fake $bad $id 1 {}|Out-Null}catch{if($_ -notmatch 'HOLD: task file ACL'){throw};$refused=$true}
 if(!$refused){throw 'Missing/empty/changed file ACL accepted'}
}
$fake.Instances=@([pscustomobject]@{InstanceGuid=$id});$fake.State=4
try {Wait-OwnerTaskExit $fake $baseline $id 1 {};throw 'Expected HOLD'} catch {if($_ -notmatch 'HOLD: owned task'){throw}}
$fake.Xml='<Changed/>'
try {Wait-OwnerTaskExit $fake $baseline $id 1 {};throw 'Expected HOLD'} catch {if($_ -notmatch 'HOLD: task registration'){throw}}
'Offline scheduler observation tests passed'
