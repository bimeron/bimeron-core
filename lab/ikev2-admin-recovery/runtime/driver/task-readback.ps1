# Inert on import. Caller must load owner-mailbox.ps1 from an explicit trusted path.
# No native helper is loaded here. TaskFileACL accepts a FileSecurity object for
# offline tests; omission reads only the named root-folder task file.
function Assert-OwnerTaskDacl {
    param([string]$Sddl, [string]$PrincipalSID, [switch]$TaskFile)
    $sd = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    if (!($sd.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -or $null -eq $sd.DiscretionaryAcl) { throw 'Missing task DACL' }
    if ($TaskFile -and (!($sd.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -or $null -eq $sd.Owner -or $sd.Owner.Value -cne 'S-1-5-32-544')) { throw 'Task file protection/owner mismatch' }
    $expected = @('S-1-5-18', 'S-1-5-32-544', $PrincipalSID)
    $full = @{}; $read = @{}
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or $ace.AceFlags -ne [Security.AccessControl.AceFlags]::None) { throw 'Unexpected task ACE type/flags' }
        $sid = $ace.SecurityIdentifier.Value
        if ($sid -cnotin $expected) { throw 'Unexpected task ACE identity' }
        if ($ace.AccessMask -eq 0x1f01ff) {
            if ($full.ContainsKey($sid)) { throw 'Duplicate task full-control ACE' }
            $full[$sid] = $true
        } elseif (!$TaskFile -and $sid -ceq $PrincipalSID -and $ace.AccessMask -eq 0x120089 -and !$read.ContainsKey($sid)) {
            # The observed scheduler expansion adds exactly one redundant FR ACE
            # for the target user. No other rights, identities or duplicates pass.
            $read[$sid] = $true
        } else { throw 'Unexpected task ACE rights' }
    }
    if ($full.Count -ne 3) { throw 'Missing task full-control ACE' }
}

function Assert-OwnerTaskReadback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Task,
        [Parameter(Mandatory)]$Definition,
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$PrincipalSID,
        $TaskFileACL
    )
    Set-StrictMode -Version Latest
    # This contract owns a task directly in the scheduler root, never a path.
    if ($TaskName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$' -or $TaskName.Contains('..')) { throw 'Invalid task basename' }
    if ((Get-OwnerPrincipalSid $PrincipalSID) -cne $PrincipalSID -or $PrincipalSID -cin @('S-1-5-18','S-1-5-32-544')) { throw 'Invalid target principal SID' }
    $read = $Task.Definition
    if ($Task.Name -cne $TaskName -or $Task.Path -cne "\$TaskName") { throw 'Task name/path mismatch' }
    foreach ($d in @($Definition, $read)) {
        if ((Get-OwnerPrincipalSid $d.Principal.UserId) -cne $PrincipalSID -or $d.Principal.LogonType -ne 3 -or $d.Principal.RunLevel -ne 1 -or ![string]::IsNullOrEmpty($d.Principal.GroupId)) { throw 'Task principal mismatch' }
        if ($d.Triggers.Count -ne 0 -or $d.Actions.Count -ne 1 -or $d.Actions.Item(1).Type -ne 0) { throw 'Task actions/triggers mismatch' }
    }
    foreach ($key in @('Path','Arguments','WorkingDirectory','Id')) {
        if ($read.Actions.Item(1).$key -cne $Definition.Actions.Item(1).$key) { throw "Task action mismatch: $key" }
    }
    # All ITaskSettings scalar fields, including defaults not set by the caller.
    # Nested settings are checked separately; COM properties are authoritative
    # for default expansion (registered XML may omit those defaults).
    foreach ($key in @('AllowDemandStart','RestartInterval','RestartCount','MultipleInstances','StopIfGoingOnBatteries','DisallowStartIfOnBatteries','AllowHardTerminate','StartWhenAvailable','RunOnlyIfNetworkAvailable','ExecutionTimeLimit','Enabled','DeleteExpiredTaskAfter','Priority','Compatibility','Hidden','RunOnlyIfIdle','WakeToRun')) {
        $optionalString=$key -in @('RestartInterval','DeleteExpiredTaskAfter')
        if ((!$optionalString -and ($null -eq $Definition.Settings.$key -or $null -eq $read.Settings.$key)) -or $read.Settings.$key -cne $Definition.Settings.$key) { throw "Task setting mismatch: $key" }
    }
    foreach ($key in @('IdleDuration','WaitTimeout','StopOnIdleEnd','RestartOnIdle')) {
        if ($null -eq $Definition.Settings.IdleSettings.$key -or $null -eq $read.Settings.IdleSettings.$key -or $read.Settings.IdleSettings.$key -cne $Definition.Settings.IdleSettings.$key) { throw "Task idle setting mismatch: $key" }
    }
    foreach ($key in @('Id','Name')) {
        if ($read.Settings.NetworkSettings.$key -cne $Definition.Settings.NetworkSettings.$key) { throw "Task network setting mismatch: $key" }
    }
    # Compare the full settings subtree from the SAME Definition API as well.
    # This covers newer settings interfaces without silently ignoring extensions.
    # Ignore only element order/formatting, never values, attributes or duplicates.
    function ConvertTo-OwnerSettingsTree($Node) {
        $attributes = @($Node.Attributes | ForEach-Object { "$($_.NamespaceURI):$($_.Name)=$($_.Value)" } | Sort-Object)
        $children = @($Node.ChildNodes | Where-Object NodeType -EQ Element | ForEach-Object { ConvertTo-OwnerSettingsTree $_ } | Sort-Object)
        $value = if ($children.Count) { '' } else { $Node.InnerText }
        ConvertTo-Json -Compress -Depth 100 -InputObject @($Node.NamespaceURI, $Node.LocalName, $attributes, $value, $children)
    }
    function Read-OwnerSettingsXml([string]$Text) {
        $doc = [xml]::new(); $doc.XmlResolver = $null
        $options = [Xml.XmlReaderSettings]::new(); $options.DtdProcessing = [Xml.DtdProcessing]::Prohibit; $options.XmlResolver = $null
        $reader = [Xml.XmlReader]::Create([IO.StringReader]::new($Text), $options)
        try { $doc.Load($reader) } finally { $reader.Dispose() }
        $nodes = $doc.SelectNodes('/*[local-name()="Task" and namespace-uri()="http://schemas.microsoft.com/windows/2004/02/mit/task"]/*[local-name()="Settings" and namespace-uri()="http://schemas.microsoft.com/windows/2004/02/mit/task"]')
        if ($nodes.Count -ne 1) { throw 'Missing/duplicate task settings XML' }
        ConvertTo-OwnerSettingsTree $nodes[0]
    }
    if ((Read-OwnerSettingsXml $read.XmlText) -cne (Read-OwnerSettingsXml $Definition.XmlText)) { throw 'Task full settings XML mismatch' }
    $xml = [string]$Task.Xml
    if ([string]::IsNullOrWhiteSpace($xml)) { throw 'Missing registered task XML' }
    $dacl = [string]$Task.GetSecurityDescriptor(4)
    $sddl = [string]$Task.GetSecurityDescriptor(7)
    Assert-OwnerTaskDacl $dacl $PrincipalSID
    Assert-OwnerTaskDacl $sddl $PrincipalSID
    if (!$PSBoundParameters.ContainsKey('TaskFileACL')) {
        $TaskFileACL = Get-Acl -LiteralPath (Join-Path $env:SystemRoot "System32/Tasks/$TaskName") -ErrorAction Stop
    }
    if ($null -eq $TaskFileACL -or !$TaskFileACL.AreAccessRulesProtected) { throw 'Task file DACL is not protected' }
    $fileSddl = $TaskFileACL.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
    Assert-OwnerTaskDacl $fileSddl $PrincipalSID -TaskFile
    # Preserve exact API representations for every subsequent baseline comparison.
    return @{ xml=$xml; sddl=$sddl; fileSddl=$fileSddl }
}
