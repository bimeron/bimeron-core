# Offline only: no scheduler, executable, VM or network operations.
. "$PSScriptRoot/owner-mailbox.ps1"
. "$PSScriptRoot/owner-supervisor.ps1"
function Assert-Test($Condition,$Message) { if (!$Condition) { throw $Message } }
$script:files=@{}; $script:writes=0; $script:fail=$true
function Publish-OwnerBytesOnce($Path,[byte[]]$Bytes) {
    $script:writes++
    if ($script:fail) { $script:fail=$false; throw 'Injected output failure' }
    if ($script:files.ContainsKey($Path) -and [Convert]::ToBase64String($script:files[$Path]) -cne [Convert]::ToBase64String($Bytes)) { throw 'Conflict' }
    $script:files[$Path]=$Bytes.Clone()
}
$script:root='memory'; $script:next=1; $script:state='READY'
$script:pending=[byte[]]@(1,2,3)
try { Complete-OwnerResponse } catch {}
Assert-Test ($script:next -eq 1 -and $null -ne $script:pending) 'Lost retry buffer'
Complete-OwnerResponse
Assert-Test ($script:next -eq 2 -and $null -eq $script:pending) 'Response did not commit'
Assert-Test ([Convert]::ToBase64String($script:files['memory/transport/responses/00000001.json']) -ceq 'AQID') 'Changed response bytes'
$script:fake=[pscustomobject]@{Id=42;ExitCode=7}
$script:owner=$script:fake; $script:identity=@{pid=42;creationFileTime='123';path='fake';sha256=('a'*64)}
$script:waits=0
function Wait-OwnerProcess($Process) { Assert-Test ([object]::ReferenceEquals($Process,$script:fake)) 'Reopened process'; $script:waits++; return $false }
$s=Get-RetainedOwnerSample
Assert-Test ($s.handleState -ceq 'live' -and $null -eq $s.exitCode) 'Live process reported exited'
function Wait-OwnerProcess($Process) { throw 'Injected disposed handle' }
$s=Get-RetainedOwnerSample
Assert-Test ($s.handleState -ceq 'unknown' -and $script:state -ceq 'HOLD') 'Wait failure manufactured exit'
$script:launchAttempted=$true; $script:sealed=$false; $script:state='HOLD'
try { Start-ExactNativeOwner $null; throw 'Unexpected launch' } catch { Assert-Test ([string]$_ -match 'Launch forbidden') 'Launch guard failed' }
'Offline supervisor checks passed'
