$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw 'Run this offline regression under Windows PowerShell 5.1'
}
function Assert-Test($Condition, [string]$Message) {
    if (!$Condition) { throw $Message }
}
function Read-TestAst([string]$Name) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $Name), [ref]$tokens, [ref]$errors)
    Assert-Test ($errors.Count -eq 0) "Parse failed: $Name $errors"
    return $ast
}
$ownerAst = Read-TestAst 'protected-guest.ps1'
$readerAst = Read-TestAst 'guest-read.ps1'
$null = Read-TestAst 'test-session-loading.ps1'
# Import exactly the real function; never evaluate either driver's dispatch body.
$definition = @($ownerAst.FindAll({param($a) $a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -ceq 'Open-OwnerSession'}, $true))
Assert-Test ($definition.Count -eq 1) 'Expected one real Open-OwnerSession'
. ([ScriptBlock]::Create($definition[0].Extent.Text))

# All external boundaries are mocked. No credentials, sessions or policies are accessed.
function Import-Clixml($Path) {
    $script:events.Add('import')
    Assert-Test ($Path -ceq (Join-Path $env:LOCALAPPDATA 'Bimeron/ikev2-clean-lab.credential.xml')) 'Credential path changed'
    return $script:credential
}
function New-PSSession($VMId, $Credential) {
    $script:events.Add('new')
    Assert-Test ($VMId -ceq '<LAB_VM_ID>') 'VM binding changed'
    Assert-Test ([object]::ReferenceEquals($Credential, $script:credential)) 'Credential binding changed'
    return $script:session
}
function Invoke-Command($Session, [scriptblock]$ScriptBlock) {
    $script:events.Add('invoke')
    Assert-Test ([object]::ReferenceEquals($Session, $script:session)) 'Remote session binding changed'
    if ($script:remoteFailure) { throw 'Injected transport failure' }
    $savedName = $env:COMPUTERNAME
    try {
        $env:COMPUTERNAME = $script:guestName
        $result = & $ScriptBlock
        if ($script:wrongReply) { return 'WRONG-REPLY' }
        return $result
    } finally { $env:COMPUTERNAME = $savedName }
}
function Get-ExecutionPolicy([string]$Scope) {
    $script:events.Add("get:$Scope")
    if ($script:getFailure) { throw 'Injected policy read failure' }
    if (!$Scope) {
        if ($script:effectiveRefusal) { return 'Restricted' }
        return $script:policies.Process
    }
    Assert-Test ($script:policies.ContainsKey($Scope)) 'Unexpected policy scope read'
    return $script:policies[$Scope]
}
function Set-ExecutionPolicy([string]$Scope, [string]$ExecutionPolicy, [switch]$Force) {
    $script:events.Add('set')
    $script:mutations.Add("${Scope}:$ExecutionPolicy")
    Assert-Test ($Scope -ceq 'Process' -and $ExecutionPolicy -ceq 'Bypass' -and $Force) 'Forbidden policy mutation'
    if ($script:setFailure) { throw 'Injected policy write failure' }
    $script:policies[$Scope] = $ExecutionPolicy
    if ($script:driftScope) { $script:policies[$script:driftScope] = 'AllSigned' }
}
function Remove-PSSession($Session) {
    $script:events.Add('remove')
    Assert-Test ([object]::ReferenceEquals($Session, $script:session)) 'Closed wrong session'
    $script:closed++
}
function Reset-Test {
    $script:events = New-Object 'Collections.Generic.List[string]'
    $script:mutations = New-Object 'Collections.Generic.List[string]'
    $script:policies = @{ MachinePolicy='Undefined'; UserPolicy='Undefined'; CurrentUser='Undefined'; LocalMachine='Undefined'; Process='Undefined' }
    $script:credential = [pscustomobject]@{Mock='credential'}
    $script:session = [pscustomobject]@{Mock='session'}
    $script:guestName = '<LAB_GUEST_NAME>'
    $script:closed = 0
    $script:effectiveRefusal = $false; $script:remoteFailure = $false
    $script:getFailure = $false; $script:setFailure = $false
    $script:wrongReply = $false; $script:driftScope = $null
}
$script:passed = 0
function Test-Admission([string]$Name, [string]$ExpectedError, [int]$ExpectedWrites) {
    $before = $script:policies.Clone()
    $result = $null; $failure = $null; $continued = $false
    try { $result = Open-OwnerSession; $continued = $true } catch { $failure = $_.Exception.Message }
    Assert-Test (($script:events | Select-Object -First 3) -join ',' -ceq 'import,new,invoke') "$Name : admission path"
    Assert-Test ($script:mutations.Count -eq $ExpectedWrites) "$Name : mutation count"
    foreach ($mutation in $script:mutations) { Assert-Test ($mutation -ceq 'Process:Bypass') "$Name : scope violation" }
    if ($ExpectedError) {
        Assert-Test ($failure -ceq $ExpectedError) "$Name : unexpected error '$failure'"
        Assert-Test (!$continued -and $null -eq $result -and $script:closed -eq 1) "$Name : refusal did not block/close"
        Assert-Test ($script:events[$script:events.Count-1] -ceq 'remove') "$Name : cleanup order"
    } else {
        Assert-Test (!$failure -and $continued -and [object]::ReferenceEquals($result, $script:session) -and $script:closed -eq 0) "$Name : successful admission failed"
        Assert-Test ($script:policies.Process -ceq 'Bypass') "$Name : process policy"
        foreach ($scope in @('MachinePolicy','UserPolicy','CurrentUser','LocalMachine')) {
            Assert-Test ($script:policies[$scope] -ceq $before[$scope]) "$Name : persistent policy mutation"
            Assert-Test (@($script:events | Where-Object { $_ -ceq "get:$scope" }).Count -ge 2) "$Name : missing before/after check"
        }
    }
    $script:passed++
    "PASS $Name"
}
Reset-Test
Test-Admission 'all scopes Undefined (fixture reproduction)' '' 1
foreach ($policy in @('Restricted','AllSigned','RemoteSigned','Bypass')) {
    Reset-Test
    $script:policies.CurrentUser = $policy; $script:policies.LocalMachine = $policy
    Test-Admission "preserve persistent $policy" '' 1
}
foreach ($scope in @('MachinePolicy','UserPolicy')) {
    foreach ($policy in @('Restricted','AllSigned','RemoteSigned','Unrestricted','Bypass')) {
        Reset-Test; $script:policies[$scope] = $policy
        Test-Admission "refuse managed $scope $policy" 'Managed execution policy present' 0
    }
}
foreach ($name in @('WRONG-GUEST','<LAB_GUEST_NAME_LOWER>','')) {
    Reset-Test; $script:guestName = $name
    Test-Admission "refuse guest '$name'" 'Guest identity mismatch' 0
    Assert-Test (@($script:events | Where-Object { $_ -like 'get:*' }).Count -eq 0) 'Wrong guest read policy'
}
Reset-Test; $script:effectiveRefusal = $true
Test-Admission 'refuse ineffective Bypass' 'Session execution policy refused' 1
foreach ($scope in @('MachinePolicy','UserPolicy','CurrentUser','LocalMachine')) {
    Reset-Test; $script:driftScope = $scope
    Test-Admission "refuse drift $scope" 'Persistent execution policy changed' 1
}
Reset-Test; $script:setFailure = $true
Test-Admission 'close on policy write exception' 'Injected policy write failure' 1
Reset-Test; $script:getFailure = $true
Test-Admission 'close on policy read exception' 'Injected policy read failure' 0
Reset-Test; $script:remoteFailure = $true
Test-Admission 'close on transport exception' 'Injected transport failure' 0
Reset-Test; $script:wrongReply = $true
Test-Admission 'close on host identity check failure' 'Guest identity mismatch' 1

# Evaluate only the actual provenance import command, never the integration body.
$imports = @($readerAst.FindAll({param($a) $a -is [Management.Automation.Language.CommandAst] -and $a.InvocationOperator -eq 'Dot' -and $a.Extent.Text -like '*$provenanceCode*'}, $true))
Assert-Test ($imports.Count -eq 1) 'Expected one provenance import'
Assert-Test ($imports[0].Extent.Text.Contains('[ScriptBlock]::Create')) 'Provenance must load from source'
$provenanceAst = Read-TestAst 'provenance.ps1'
Assert-Test ($null -eq $provenanceAst.Find({param($a) $a -is [Management.Automation.Language.VariableExpressionAst] -and $a.VariablePath.UserPath -ieq 'PSScriptRoot'}, $true)) 'Provenance depends on PSScriptRoot'
$provenanceCode = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'provenance.ps1'))
. ([ScriptBlock]::Create($imports[0].Extent.Text))
foreach ($name in @('Get-ProbeRegistration','Assert-ProbeRegistration','Assert-ProbeProvenance','Test-ProbeCimCreation')) {
    Assert-Test ($null -ne (Get-Command $name -CommandType Function -ErrorAction SilentlyContinue)) "Missing imported function $name"
}
Assert-Test (Test-ProbeCimCreation ([datetime]'2026-11-04T00:00:00Z') '2026-11-04T00:00:00.0000009Z') 'Imported helper behavior'
"PASS provenance source import; $script:passed admission scenarios; Windows PowerShell $($PSVersionTable.PSVersion)"
foreach ($name in @('protected-guest.ps1','guest-read.ps1','test-session-loading.ps1')) {
    Get-FileHash (Join-Path $PSScriptRoot $name) -Algorithm SHA256 | Select-Object Hash, Path
}
