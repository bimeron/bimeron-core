# Offline only: no scheduler activation, guest access, native helper, or task writes.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. "$PSScriptRoot/owner-mailbox.ps1"
. "$PSScriptRoot/task-readback.ps1"
# The captured rules contain both value and Value keys; preserve them with a map.
$fixture = Get-Content "$PSScriptRoot/../fixture/task-representation.json" -Raw | ConvertFrom-Json -AsHashtable
$remainder = Get-Content "$PSScriptRoot/../fixture/registration-remainder-check.json" -Raw | ConvertFrom-Json
$sid = $remainder.principalSID
[xml]$captured = $fixture.definitionXml
$name = ([string]$captured.Task.RegistrationInfo.URI).TrimStart('\')
function New-Definition {
    [xml]$x = $fixture.definitionXml
    $s = $x.Task.Settings
    $settings = [pscustomobject]@{
        AllowDemandStart=($s.AllowStartOnDemand -ceq 'true'); RestartInterval=''; RestartCount=0
        MultipleInstances=2; StopIfGoingOnBatteries=($s.StopIfGoingOnBatteries -ceq 'true')
        DisallowStartIfOnBatteries=($s.DisallowStartIfOnBatteries -ceq 'true')
        AllowHardTerminate=($s.AllowHardTerminate -ceq 'true'); StartWhenAvailable=($s.StartWhenAvailable -ceq 'true')
        RunOnlyIfNetworkAvailable=($s.RunOnlyIfNetworkAvailable -ceq 'true'); ExecutionTimeLimit=[string]$s.ExecutionTimeLimit
        Enabled=($s.Enabled -ceq 'true'); DeleteExpiredTaskAfter=''; Priority=[int]$s.Priority; Compatibility=2
        Hidden=($s.Hidden -ceq 'true'); RunOnlyIfIdle=($s.RunOnlyIfIdle -ceq 'true'); WakeToRun=($s.WakeToRun -ceq 'true')
        IdleSettings=[pscustomobject]@{IdleDuration=[string]$s.IdleSettings.Duration; WaitTimeout=[string]$s.IdleSettings.WaitTimeout; StopOnIdleEnd=($s.IdleSettings.StopOnIdleEnd -ceq 'true'); RestartOnIdle=($s.IdleSettings.RestartOnIdle -ceq 'true')}
        NetworkSettings=[pscustomobject]@{Id=''; Name=''}
    }
    $action = [pscustomobject]@{Type=0; Path=[string]$x.Task.Actions.Exec.Command; Arguments=[string]$x.Task.Actions.Exec.Arguments; WorkingDirectory=''; Id=''}
    $actions = [pscustomobject]@{Count=1; Entry=$action}
    $actions | Add-Member ScriptMethod Item {param($index) if($index -ne 1){throw 'Unexpected action index'}; $this.Entry}
    [pscustomobject]@{Principal=[pscustomobject]@{UserId=[string]$x.Task.Principals.Principal.UserId; LogonType=3; RunLevel=1; GroupId=''}; Actions=$actions; Triggers=[pscustomobject]@{Count=0}; Settings=$settings; XmlText=$fixture.definitionXml}
}
function New-Case {
    $task = [pscustomobject]@{Name=$name; Path="\$name"; Definition=(New-Definition); Xml=$fixture.xml; Dacl=$remainder.dacl; Sddl="O:BAG:BA$($remainder.dacl)"}
    $task | Add-Member ScriptMethod GetSecurityDescriptor {param($flags) if($flags -eq 4){$this.Dacl}elseif($flags -eq 7){$this.Sddl}else{throw 'Unexpected security flags'}}
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($fixture.fileSddl)
    @{Task=$task; Definition=(New-Definition); TaskName=$name; PrincipalSID=$sid; TaskFileACL=$acl}
}
$script:passed = 0
function Reject([string]$Label, [scriptblock]$Mutate) {
    $case = New-Case
    & $Mutate $case
    $rejected = $false
    try { $null = Assert-OwnerTaskReadback @case } catch { $rejected = $true }
    if (!$rejected) { throw "Accepted invalid case: $Label" }
    $script:passed++
}
$case = New-Case
if ($case.Task.Xml -ceq $case.Task.Definition.XmlText) { throw 'Fixture lost serializer difference' }
$baseline = Assert-OwnerTaskReadback @case
if ($baseline.xml -cne $fixture.xml -or $baseline.sddl -cne $case.Task.Sddl -or $baseline.fileSddl -cne $fixture.fileSddl) { throw 'Baseline changed exact representations' }
$script:passed++
$case.Task.Dacl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$sid)"
$null = Assert-OwnerTaskReadback @case
$script:passed++
# Same-API settings comparison tolerates element order only, preserving values.
$case = New-Case
[xml]$reordered = $case.Task.Definition.XmlText
$settingsNode = $reordered.Task.Settings
$null = $settingsNode.AppendChild($settingsNode.FirstChild)
$case.Task.Definition.XmlText = $reordered.OuterXml
$null = Assert-OwnerTaskReadback @case
$script:passed++
Reject 'file protection property' {param($c) $c.TaskFileACL=[pscustomobject]@{AreAccessRulesProtected=$false}}
Reject 'principal' {param($c) $c.Task.Definition.Principal.UserId='S-1-5-18'}
Reject 'intended principal' {param($c) $c.Definition.Principal.UserId='S-1-5-18'}
Reject 'logon type' {param($c) $c.Task.Definition.Principal.LogonType=5}
Reject 'run level' {param($c) $c.Task.Definition.Principal.RunLevel=0}
Reject 'group principal' {param($c) $c.Task.Definition.Principal.GroupId='S-1-5-32-544'}
Reject 'task name' {param($c) $c.Task.Name='Other'}
Reject 'task path' {param($c) $c.Task.Path='\Other'}
Reject 'path traversal' {param($c) $c.TaskName='../other'}
Reject 'trigger' {param($c) $c.Task.Definition.Triggers.Count=1}
Reject 'extra action' {param($c) $c.Task.Definition.Actions.Count=2}
Reject 'missing action' {param($c) $c.Task.Definition.Actions.Count=0}
Reject 'action type' {param($c) $c.Task.Definition.Actions.Entry.Type=5}
foreach ($key in @('Path','Arguments','WorkingDirectory','Id')) {
    Reject "action $key" {param($c) $c.Task.Definition.Actions.Entry.$key='changed'}
}
foreach ($key in (New-Definition).Settings.PSObject.Properties.Name | Where-Object {$_ -notin @('IdleSettings','NetworkSettings')}) {
    Reject "setting $key" {param($c) $old=$c.Task.Definition.Settings.$key; $c.Task.Definition.Settings.$key=if($old -is [bool]){!$old}elseif($old -is [int]){$old+1}else{'changed'}}
}
foreach ($key in @('IdleDuration','WaitTimeout','StopOnIdleEnd','RestartOnIdle')) {
    Reject "idle $key" {param($c) $old=$c.Task.Definition.Settings.IdleSettings.$key; $c.Task.Definition.Settings.IdleSettings.$key=if($old -is [bool]){!$old}else{'changed'}}
}
foreach ($key in @('Id','Name')) { Reject "network $key" {param($c) $c.Task.Definition.Settings.NetworkSettings.$key='changed'} }
Reject 'extension settings' {param($c) $c.Task.Definition.XmlText=$c.Task.Definition.XmlText.Replace('</Settings>','<UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine></Settings>')}
Reject 'duplicate XML setting' {param($c) $c.Task.Definition.XmlText=$c.Task.Definition.XmlText.Replace('</Settings>','<Priority>7</Priority></Settings>')}
Reject 'missing field' {param($c) $c.Task.Definition.Settings.PSObject.Properties.Remove('RestartCount')}
Reject 'empty scheduler XML' {param($c) $c.Task.Xml=''}
foreach ($bad in @(
    "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$sid)(A;;FA;;;WD)",
    "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$sid)(A;;FW;;;$sid)",
    "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$sid)(A;;FR;;;SY)",
    "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$sid)(A;;FR;;;$sid)(A;;FR;;;$sid)",
    "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;$sid)",
    "D:(A;;FA;;;SY)(A;;FA;;;BA)(D;;FA;;;$sid)",
    "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;ID;FA;;;$sid)",
    "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;OI;FA;;;$sid)",
    "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$sid)(A;;FA;;;$sid)",
    'D:'
)) {
    Reject 'API DACL' {param($c) $c.Task.Dacl=$bad}
    Reject 'full API SDDL' {param($c) $c.Task.Sddl="O:BAG:BA$bad"}
}
foreach ($bad in @(
    $fixture.fileSddl.Replace('D:PAI','D:AI'),
    $fixture.fileSddl.Replace('O:BA','O:SY'),
    ($fixture.fileSddl + '(A;;FA;;;WD)'),
    ($fixture.fileSddl + "(A;;FR;;;$sid)"),
    $fixture.fileSddl.Replace('(A;;FA;;;SY)','(D;;FA;;;SY)'),
    $fixture.fileSddl.Replace('(A;;FA;;;SY)','(A;ID;FA;;;SY)'),
    $fixture.fileSddl.Replace('(A;;FA;;;SY)','(A;;FR;;;SY)')
)) { Reject "file ACL $bad" {param($c) $c.TaskFileACL=[pscustomobject]@{AreAccessRulesProtected=$true; Raw=$bad}; $c.TaskFileACL | Add-Member ScriptMethod GetSecurityDescriptorSddlForm {param($sections) $this.Raw}} }
Reject 'null ACL' {param($c) $c.TaskFileACL=$null}
# Fresh COM definitions return null for these two optional duration strings.
$case = New-Case
foreach ($key in @('RestartInterval','DeleteExpiredTaskAfter')) {
    $case.Definition.Settings.$key = $null
    $case.Task.Definition.Settings.$key = $null
}
$null = Assert-OwnerTaskReadback @case
$script:passed++
foreach ($key in @('RestartInterval','DeleteExpiredTaskAfter')) {
    foreach ($value in @('', 'PT1M')) {
        Reject "$key intended null/readback value '$value'" {param($c) $c.Definition.Settings.$key=$null; $c.Task.Definition.Settings.$key=$value}
        Reject "$key intended value '$value'/readback null" {param($c) $c.Definition.Settings.$key=$value; $c.Task.Definition.Settings.$key=$null}
    }
}
foreach ($key in (New-Definition).Settings.PSObject.Properties.Name | Where-Object {$_ -notin @('IdleSettings','NetworkSettings','RestartInterval','DeleteExpiredTaskAfter')}) {
    Reject "$key mandatory scalar both null" {param($c) $c.Definition.Settings.$key=$null; $c.Task.Definition.Settings.$key=$null}
}
Write-Output "PASS: $script:passed offline task readback cases"



