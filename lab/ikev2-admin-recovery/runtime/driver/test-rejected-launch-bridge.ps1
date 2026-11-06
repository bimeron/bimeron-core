# Offline persistent mailbox bridge. Only external identity/scheduler/process facts
# are replaced; command parsing, proof validation, state transitions and I/O are real.
param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/owner-mailbox.ps1"
. "$PSScriptRoot/owner-supervisor.ps1"
. "$PSScriptRoot/owner-bindings.ps1"
$script:root=$Root
$script:startCalls=0
function Start-OwnerProcess { $script:startCalls++; throw 'FORBIDDEN native process launch' }
function Get-OwnerInstanceFacts { @{principalSid=$script:config.principalSid;elevated=$true;sessionId=2;pid=99;creationFileTime='123'} }
function Get-Acl {param($LiteralPath,$ErrorAction)
    if([IO.Path]::GetFileName($LiteralPath) -cne $script:config.taskName){throw 'Wrong task ACL path'}
    $acl=[pscustomobject]@{};$acl|Add-Member ScriptMethod GetSecurityDescriptorSddlForm {param($sections)'offline-file-acl'};$acl
}
function Get-OwnerRegisteredTask($Name) {
    $task=[pscustomobject]@{Xml='offline-task';Definition=[pscustomobject]@{
        Principal=[pscustomobject]@{UserId=$script:config.principalSid;RunLevel=1;LogonType=3}
        Triggers=@();Actions=@('offline');Settings=[pscustomobject]@{RestartCount=0;ExecutionTimeLimit='PT0S';AllowHardTerminate=$false}}}
    $task | Add-Member ScriptMethod GetSecurityDescriptor {param($flags) 'offline-acl'}
    return $task
}
while ($null -ne ($line=[Console]::ReadLine())) {
    try {
        $request=ConvertFrom-Json $line
        switch ($request.mode) {
            'preflight' {
                $bytes=Read-OwnerBytes "$Root/transport/config.json" -Root $Root
                $script:config=Assert-StrictOwnerJson $bytes
                $script:nonce=$script:config.nonce
                $script:configHash=Get-OwnerSHA256 $bytes
                # Hostname is an external fact; override only in this child process.
                $env:COMPUTERNAME=$script:config.guest
                $script:onceHash=Initialize-OwnerInstance $Root $script:config $script:configHash
                $script:owner=$null;$script:ownerHandle=$null;$script:identity=$null
                $script:launchAttempted=$false;$script:sealed=$false;$script:exitProof=$null
                $script:cleanupHash=$null;$script:state='READY';$script:next=1
                $script:pending=$null;$script:relay=@{};$script:diagnostic=$null
                $raw=Read-OwnerBytes "$Root/transport/proofs/supervisor-once.json" -Root $Root
            }
            'submit' {
                $packet=Read-NextOwnerCommand $script:next
                if (!$packet) {throw 'Missing submitted command'}
                Invoke-OwnerCommand $packet
                $raw=Read-OwnerBytes ("$Root/transport/responses/{0:D8}.json" -f $request.seq) -Root $Root
            }
            'fetch' {
                # Deliberately never dispatch or advance the supervisor on fetch.
                $raw=Read-OwnerBytes ("$Root/transport/responses/{0:D8}.json" -f $request.seq) -Root $Root
            }
            'fault' {
                # Explicit adversarial state setup, never a substitute command handler.
                $script:state=$request.state;$script:launchAttempted=[bool]$request.launchAttempted
                $raw=[byte[]]@()
            }
            'inspect' { $raw=[byte[]]@() }
            default {throw 'Unknown bridge operation'}
        }
        $result=@{ok=$true;raw=[Convert]::ToBase64String($raw);state=$script:state;launchAttempted=$script:launchAttempted;startCalls=$script:startCalls;next=$script:next;once=$script:onceHash}
    } catch { $result=@{ok=$false;error=[string]$_} }
    [Console]::WriteLine(($result|ConvertTo-Json -Depth 10 -Compress))
}
