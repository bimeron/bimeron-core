param([string]$Driver,[string]$Output,[string]$Nonce,[ValidateSet('early','deployed','release-refused')][string]$Scenario='early')
$ErrorActionPreference='Stop'
# Execute the complete preparation entry point in an isolated temporary tree.
# Every VM, task, credential, native command and session boundary is mocked.
$fixture=Split-Path $Driver
$guest=Join-Path $fixture 'guest'
$ordinary=Join-Path $fixture 'ordinary.ps1'
[IO.File]::WriteAllText($ordinary,'offline original wrapper')
$sessionObject=[pscustomobject]@{InstanceId=[guid]::NewGuid();State='Opened';Availability='Available'}
$task=[pscustomobject]@{Path='\BimeronStep8Probe';Xml='<Task>offline PT20M</Task>';State=3}
$task|Add-Member ScriptMethod GetSecurityDescriptor {param($flags) 'offline-exact-sddl'}
$task|Add-Member ScriptMethod GetInstances {param($flags) @()}
$folder=[pscustomobject]@{Task=$task};$folder|Add-Member ScriptMethod GetTask {param($name) $this.Task}
$service=[pscustomobject]@{Folder=$folder};$service|Add-Member ScriptMethod Connect {}; $service|Add-Member ScriptMethod GetFolder {param($name) $this.Folder}
$script:baselineSeen=$false;$script:waits=0
function Import-Clixml {'offline-credential'}
function New-PSSession {param($VMId,$Credential) $sessionObject}
function Remove-PSSession {param($Session)
 if(!(Test-Path "$Output/preparation-release.json") -or !(Test-Path "$Output/restore-permit.json")){throw 'Offline: session release without both permits'}
 if(![object]::ReferenceEquals($Session,$sessionObject)){throw 'Offline: replacement session'}
 $Session.State='Closed'
}
function Get-ScheduledTask {param($TaskName) [pscustomobject]@{State='Ready';Actions=@();Principal=[pscustomobject]@{UserId='offline';RunLevel='Limited'}}}
function Get-Process {param($Name) @()}
# Guest service/port facts are fixtures; never read this host's IKE state.
function Get-Service {param($Name) [pscustomobject]@{Name=$Name;Status='Stopped'}}
function Get-NetUDPEndpoint {param($ErrorAction) @()}
function Get-FileHash {param($Path) [pscustomobject]@{Hash=(Get-ProbeFileSHA256 $Path)}}
function Get-ExecutionPolicy {param([switch]$List,$Scope)
 if($List){0..4|ForEach-Object {[pscustomobject]@{Scope=$_;ExecutionPolicy=0}}}else{'Undefined'}
}
function New-Object {param($ComObject) if($ComObject -cne 'Schedule.Service'){throw 'Unexpected COM'};$service}
function rasdial {'No connections'}
function icacls {$global:LASTEXITCODE=0}
function netsh {param($a,$b,$c,$file) [IO.File]::WriteAllText($file.Substring(5),'<wfpstate/>');$global:LASTEXITCODE=0}
function Get-Content {param([switch]$Raw,[string]$Path)
 if($Path -like '*step9-abi*expected.json') {return (@{guids=@(1..22|ForEach-Object {[guid]::NewGuid().ToString()})}|ConvertTo-Json)}
 Microsoft.PowerShell.Management\Get-Content -LiteralPath $Path -Raw:$Raw
}
function Start-Process {throw 'Forbidden offline native/process start'}
function Copy-Item {param($FromSession,$ToSession,$LiteralPath,$Destination,[switch]$Recurse)
 if($ToSession){throw 'Injected refusal after deployment intent'}
 if(!$FromSession){throw 'Unexpected copy boundary'}
 Microsoft.PowerShell.Management\Copy-Item -LiteralPath $guest -Destination $Destination -Recurse:$Recurse
}
function Start-Sleep {param($Milliseconds)
 if($Milliseconds -eq 250){$script:waits++}
 if($script:waits -gt 48){throw 'Offline harness observation bound'}
 # Negative cases leave ownership held in production. End only this mock to
 # inspect refusal, never turn timeout into successful release.
 if($Scenario -ne 'early' -and $script:waits -gt 2){throw 'Offline HOLD observed'}
 Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds $Milliseconds
}
function Invoke-Command {param($Session,$ArgumentList,$ScriptBlock,[switch]$AsJob)
 if($AsJob -or ![object]::ReferenceEquals($Session,$sessionObject)){throw 'Forbidden inspector/replacement session'}
 $argsCopy=@($ArgumentList)
 for($i=0;$i -lt $argsCopy.Count;$i++){if($argsCopy[$i] -is [string]){$argsCopy[$i]=$argsCopy[$i].Replace("C:/BimeronStep10Probe/$Nonce",$guest.Replace('\','/')).Replace('C:/BimeronStep8/probe.ps1',$ordinary.Replace('\','/'))}}
 $body=$ScriptBlock.ToString().Replace('C:/BimeronStep8/probe.ps1',$ordinary.Replace('\','/'))
 # Absolute native images bypass the function mocks above: route each one to
 # its mock and refuse any remaining absolute native invocation.
 foreach($tool in 'rasdial','netsh','icacls'){$body=$body.Replace("& 'C:/Windows/System32/$tool.exe'",$tool)}
 if($body -match "&\s*'[A-Za-z]:[\\/][^']*\.exe'"){throw 'Offline: unmocked absolute native invocation'}
 $value=& ([scriptblock]::Create($body)) @argsCopy
 if(!$script:baselineSeen -and $body.Contains('preflight-bfe.xml')){
  $script:baselineSeen=$true
  if($Scenario -ne 'deployed'){
   Publish-ProbeStop "$Output/stop-request.json" ([pscustomobject]@{schema=1;nonce=$Nonce;requestId='offline-request';reasonCode='offline-injected-early-failure';requestedUtc=[DateTime]::UtcNow.ToString('o')}) $Nonce
  }
 }
 $value
}
$savedName=$env:COMPUTERNAME;$env:COMPUTERNAME='<LAB_GUEST_NAME>'
try{& "$Driver/prepare-task.ps1" -Nonce $Nonce -ControlPath $Output -ProducerSeconds 900 -TaskDuration PT20M}
finally{$env:COMPUTERNAME=$savedName}
