# Thin helper for dispose-held-run.py. One JSON line on stdout per call.
# The run nonce comes from the operator-approved plan (64 hex, validated).
# Guest steps open a NEW PS Direct session through the fixed Open-OwnerSession
# (never the resident's session) and always remove it. No file is written on
# the host. host-network and host-processes are read-only.
param(
 [Parameter(Mandatory=$true)][ValidateSet('guest-state','guest-remove','host-network','host-processes')][string]$Step,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$RunNonce,
 [Parameter(Mandatory=$true)][string]$Driver
)
$ErrorActionPreference='Stop'
# ValidatePattern is case-insensitive; the run nonce is exactly lowercase hex.
if($RunNonce -cnotmatch '^[a-f0-9]{64}$'){throw 'Run nonce format'}
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if($Step -ceq 'host-network'){
 $snap=[ordered]@{schema='host-network-readonly-v1';utc=[DateTime]::UtcNow.ToString('o')
  sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  adapters=@(Get-NetAdapter -IncludeHidden|Sort-Object InterfaceGuid|Select-Object Name,InterfaceDescription,InterfaceGuid,ifIndex,Status,MacAddress)
  # Journaled only: link speed renegotiates by itself and is not compared.
  adapterLinkSpeeds=@(Get-NetAdapter -IncludeHidden|Sort-Object InterfaceGuid|Select-Object InterfaceGuid,LinkSpeed)
  routes=@(Get-NetRoute|Sort-Object AddressFamily,InterfaceIndex,DestinationPrefix,NextHop|Select-Object AddressFamily,InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,Protocol,State)
  # Journaled only: router-advertised IPv6 DNS changes by itself and is not compared.
  dns=@(Get-DnsClientServerAddress|Sort-Object InterfaceIndex,AddressFamily|Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
  vpnUser=@(Get-VpnConnection|Select-Object Name,ConnectionStatus,Guid,TunnelType)
  vpnAllUsers=@(Get-VpnConnection -AllUserConnection|Select-Object Name,ConnectionStatus,Guid,TunnelType)}
 $snap|ConvertTo-Json -Depth 9 -Compress
 return
}
if($Step -ceq 'host-processes'){
 # Exact FILETIME creation; the caller excludes itself and this helper ($PID).
 $rows=@(Get-CimInstance Win32_Process|Sort-Object ProcessId|ForEach-Object {[ordered]@{pid=[int]$_.ProcessId;parent=[int]$_.ParentProcessId
  name=[string]$_.Name;image=[string]$_.ExecutablePath;commandLine=[string]$_.CommandLine
  creationFileTime=if($_.CreationDate){[long]$_.CreationDate.ToFileTimeUtc()}else{$null}}})
 [ordered]@{schema='host-processes-readonly-v1';self=[int]$PID;processes=$rows}|ConvertTo-Json -Depth 5 -Compress
 return
}
if(!(Test-Path -LiteralPath (Join-Path $Driver 'protected-guest.ps1') -PathType Leaf)){throw 'Fixed driver path absent'}
# Dot-sourcing defines protected-guest's parameters in this scope; rebind Nonce.
. (Join-Path $Driver 'protected-guest.ps1')
$Nonce=$RunNonce
$state={
 param($nonce)
 $ErrorActionPreference='Stop'
 if($env:COMPUTERNAME -cne '<LAB_GUEST_NAME>'){throw 'Guest identity mismatch'}
 $root="C:/BimeronFull300/$nonce";$probe="C:/BimeronStep10Probe/$nonce"
 function Names($p){if(Test-Path -LiteralPath $p){@(Get-ChildItem -LiteralPath $p -Force|ForEach-Object {$_.Name})}else{@()}}
 $svc=New-Object -ComObject Schedule.Service;$svc.Connect();$folder=$svc.GetFolder('\')
 $tasks=@($folder.GetTasks(1)|Where-Object {$_.Name -ceq "BimeronFull300Owner-$nonce"}|ForEach-Object {@{state=[int]$_.State;instances=@($_.GetInstances(0)|ForEach-Object {[string]$_.InstanceGuid})}})
 $processes=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -ieq 'full300-owner.exe' -or ($_.CommandLine -and $_.CommandLine.Contains($nonce))}|ForEach-Object {@{pid=[int]$_.ProcessId;name=[string]$_.Name;commandLine=[string]$_.CommandLine}})
 $udp=@(Get-NetUDPEndpoint -ErrorAction Stop|Where-Object {$_.LocalPort -in @(500,4500)}|ForEach-Object {@{address=[string]$_.LocalAddress;port=[int]$_.LocalPort;pid=[int]$_.OwningProcess}})
 $services=@{};foreach($n in @('BFE','RasMan','IKEEXT','PolicyAgent')){$services[$n]=[string](Get-Service $n).Status}
 # Process scope belongs to this disposable session (set to Bypass on admission).
 $policy=@{};foreach($s in @('MachinePolicy','UserPolicy','CurrentUser','LocalMachine')){$policy[$s]=[string](Get-ExecutionPolicy -Scope $s)}
 $ras=[string](& 'C:/Windows/System32/rasdial.exe'|Out-String)
 @{schema='held-run-guest-state-v1';nonce=$nonce;computer=$env:COMPUTERNAME;rootExists=(Test-Path -LiteralPath $root);probeExists=(Test-Path -LiteralPath $probe);commands=@(Names "$root/transport/commands");responses=@(Names "$root/transport/responses");noLaunch=(Test-Path -LiteralPath "$root/transport/proofs/no-launch.json");tasks=$tasks;processes=$processes;udp=$udp;services=$services;policy=$policy;ras=$ras}|ConvertTo-Json -Depth 8 -Compress
}
$remove={
 param($nonce)
 $ErrorActionPreference='Stop'
 function Assert-NoReparseChain([string]$path){
  for($a=Get-Item -LiteralPath $path -Force;$null -ne $a;$a=$a.Parent){
   if($a.Attributes -band [IO.FileAttributes]::ReparsePoint){throw "Reparse ancestor: $($a.FullName)"}
  }
 }
 if($env:COMPUTERNAME -cne '<LAB_GUEST_NAME>'){throw 'Guest identity mismatch'}
 if($nonce -cnotmatch '^[a-f0-9]{64}$'){throw 'Removal nonce'}
 # Exactly these two run directories; nothing else is ever a target.
 $targets=@("C:/BimeronFull300/$nonce","C:/BimeronStep10Probe/$nonce")
 # The parents and every ancestor must be real directories (as protected-guest.ps1 admission).
 foreach($parent in @('C:/BimeronFull300','C:/BimeronStep10Probe')){if(Test-Path -LiteralPath $parent){Assert-NoReparseChain $parent}}
 foreach($t in $targets){
  if(!(Test-Path -LiteralPath $t)){continue}
  $item=Get-Item -LiteralPath $t -Force
  if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Name -cne $nonce){throw 'Unsafe removal target'}
  if(@(Get-ChildItem -LiteralPath $t -Recurse -Force|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'Reparse point below removal target'}
 }
 foreach($t in $targets){if(Test-Path -LiteralPath $t){Remove-Item -LiteralPath $t -Recurse -Force}}
 @{targets=$targets;absent=@($targets|ForEach-Object {!(Test-Path -LiteralPath $_)})}|ConvertTo-Json -Depth 4 -Compress
}
$session=Open-OwnerSession
try{
 $body=if($Step -ceq 'guest-state'){$state}else{$remove}
 $value=Invoke-Command -Session $session -ScriptBlock $body -ArgumentList $RunNonce
 if(@($value).Count -ne 1 -or $value -isnot [string]){throw 'Guest helper output shape'}
 $value
}finally{Remove-PSSession -Session $session}
