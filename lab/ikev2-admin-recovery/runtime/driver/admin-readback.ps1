# Source-derived readback through the retained original session. Dot-source is inert.
function Read-AdministrativeGuest($Session,[string]$Operation) {
 if($null -eq $Session -or [string]$Session.State -cne 'Opened'){throw 'Original readback session unavailable'}
 switch -CaseSensitive ($Operation) {
  'guest' { $value=Invoke-Command -Session $Session -ScriptBlock {
  $ErrorActionPreference='Stop'
  if($env:COMPUTERNAME -cne '<LAB_GUEST_NAME>'){throw 'Guest identity mismatch'}
  function Settings($v){if($null -eq $v){return $null};if($v -is [Microsoft.Management.Infrastructure.CimInstance]){$r=[ordered]@{};foreach($p in @($v.CimInstanceProperties|Sort-Object Name)){$r[$p.Name]=Settings $p.Value};return $r};if($v -is [array]){return ,@($v|ForEach-Object {Settings $_})};return $v}
  $sid=(New-Object Security.Principal.NTAccount($env:COMPUTERNAME,'test')).Translate([Security.Principal.SecurityIdentifier]).Value
  if($sid -cne '<LAB_GUEST_SID_1001>'){throw 'Wrong test SID'}
  $query=& (Join-Path $env:SystemRoot 'System32/quser.exe') test 2>&1|Out-String;$queryExit=$LASTEXITCODE
  if($query -notmatch '(?m)^\s*>?test\s+\S+\s+2\s+Active\s+'){throw 'Exact active session missing'}
  $shells=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|ForEach-Object {$o=Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid;@{pid=$_.ProcessId;session=$_.SessionId;sid=$o.Sid;result=$o.ReturnValue}})
  if(!@($shells|Where-Object {$_.session -eq 2 -and $_.sid -ceq $sid -and $_.result -eq 0}).Count){throw 'Exact explorer owner missing'}
  $profile=(Get-CimInstance Win32_UserProfile|Where-Object SID -CEQ $sid).LocalPath
  $temp=Join-Path $profile 'AppData/Local/Temp'
  if(!$profile -or !(Test-Path -LiteralPath $temp -PathType Container) -or $temp.Length -gt 204 -or $env:TEMP.Length -gt 204){throw 'TEMP envelope failed'}
  $svc=New-Object -ComObject Schedule.Service;$svc.Connect();$t=$svc.GetFolder('\').GetTask('BimeronStep8Probe')
  @{utc=[DateTime]::UtcNow.ToString('o');computer=$env:COMPUTERNAME;testSid=$sid;shells=$shells;query=$query;queryExit=$queryExit;testTemp=$temp;adminTemp=$env:TEMP;systemRoot=$env:SystemRoot;task=@{xml=$t.Xml;sddl=$t.GetSecurityDescriptor(7);state=[int]$t.State;instances=$t.GetInstances(0).Count;settings=(Settings (Get-ScheduledTask BimeronStep8Probe).Settings|ConvertTo-Json -Depth 30 -Compress)};wrapperSHA256=(Get-FileHash C:/BimeronStep8/probe.ps1).Hash;policy=@(Get-ExecutionPolicy -List|Select-Object Scope,ExecutionPolicy)}
 }; if($null -eq $value){throw 'Administrative readback produced no value'}; return ($value|ConvertTo-Json -Depth 40 -Compress) }
  'services' { $value=Invoke-Command -Session $Session -ScriptBlock {
  $ErrorActionPreference='Stop'
  if($env:COMPUTERNAME -cne '<LAB_GUEST_NAME>'){throw 'Guest identity mismatch'}
  $m=@{};foreach($n in @('BFE','RasMan','IKEEXT','PolicyAgent')){$m[$n]=[string](Get-Service $n).Status};$m
 }; if($value -isnot [Collections.IDictionary]){throw 'Service readback incomplete'}
 $m=@{};foreach($n in @('BFE','RasMan','IKEEXT','PolicyAgent')){if(!$value.Contains($n) -or $value[$n] -isnot [string] -or !$value[$n]){throw 'Service readback incomplete'};$m[$n]=$value[$n]};return ($m|ConvertTo-Json -Depth 40 -Compress) }
  'absence' { $value=Invoke-Command -Session $Session -ScriptBlock {
  $ErrorActionPreference='Stop'
  if($env:COMPUTERNAME -cne '<LAB_GUEST_NAME>'){throw 'Guest binding mismatch'}
  $svc=New-Object -ComObject Schedule.Service;$svc.Connect();$folder=$svc.GetFolder('\')
  $task=$folder.GetTask('BimeronStep8Probe');$reference=$folder.GetTask('BimeronStep9ABIActual')
  $shells=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|ForEach-Object {$owner=Invoke-CimMethod -InputObject $_ -MethodName GetOwner;@{pid=$_.ProcessId;session=$_.SessionId;account="$($owner.Domain)\$($owner.User)";ownerResult=$owner.ReturnValue}})
  $owners=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -in @('full300-owner.exe','step10-candidate.exe') -or ($_.CommandLine -and $_.CommandLine -match 'BimeronFull300|BimeronStep10Probe[\\/].*[\\/](probe|inspect-producer).ps1')}|Select-Object ProcessId,Name,CreationDate,ExecutablePath)
  @{guest=$env:COMPUTERNAME;console=(Get-CimInstance Win32_ComputerSystem).UserName;shells=$shells;owners=$owners;task=@{xml=$task.Xml;sddl=$task.GetSecurityDescriptor(7);state=[int]$task.State;instances=$task.GetInstances(0).Count;duration=$task.Definition.Settings.ExecutionTimeLimit};wrapper=(Get-FileHash C:/BimeronStep8/probe.ps1).Hash;reference=@{user=$reference.Definition.Principal.UserId;logon=$reference.Definition.Principal.LogonType;level=$reference.Definition.Principal.RunLevel};dedicatedTasks=@($folder.GetTasks(1)|Where-Object Name -Like 'BimeronFull300*'|Select-Object Name,State);ras=(& 'C:/Windows/System32/rasdial.exe'|Out-String)}
 }; if($null -eq $value){throw 'Administrative readback produced no value'}; return ($value|ConvertTo-Json -Depth 40 -Compress) }
  default {throw 'Administrative readback allowlist'}
 }
}
