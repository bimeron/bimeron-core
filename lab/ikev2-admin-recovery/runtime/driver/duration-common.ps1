$ErrorActionPreference='Stop'
if(!('DurationXml' -as [type])){if($PSVersionTable.PSEdition -eq 'Core'){Add-Type -Path "$PSScriptRoot/DurationXml.cs"}else{Add-Type -Path "$PSScriptRoot/DurationXml.cs" -ReferencedAssemblies System.Xml,System.Core}}
. "$PSScriptRoot/file-sha256.ps1"
. "$PSScriptRoot/provenance.ps1"
function Convert-DurationCim($Value) {
 if($null -eq $Value){return $null}
 if($Value -is [Microsoft.Management.Infrastructure.CimInstance]){
  $properties=@(foreach($p in @($Value.CimInstanceProperties|Sort-Object Name)){[ordered]@{name=$p.Name;type=[string]$p.CimType;flags=[string]$p.Flags;value=(Convert-DurationCim $p.Value)}})
  return [ordered]@{class=$Value.CimSystemProperties.ClassName;namespace=$Value.CimSystemProperties.Namespace;server=$Value.CimSystemProperties.ServerName;properties=$properties}
 }
 if($Value -is [array]){return ,@($Value|ForEach-Object {Convert-DurationCim $_})}
 return $Value
}
function Get-DurationSettings($Value){return (Convert-DurationCim $Value|ConvertTo-Json -Depth 30 -Compress)}
function Assert-DurationIdle($Task) {
 if($Task.State -ne 3 -or $Task.GetInstances(0).Count -ne 0){throw 'Task not definitively idle'}
 $processes=@(Get-CimInstance Win32_Process |Where-Object {$_.CommandLine -and ($_.CommandLine -match 'BimeronStep8[\\/]probe\.ps1' -or $_.CommandLine -match 'BimeronStep10Probe[\\/][a-f0-9]{64}[\\/]probe\.ps1')})
 if($processes.Count){throw 'Ordinary wrapper/producer process remains'}
}
function Get-DurationSnapshot {
 $svc=New-Object -ComObject Schedule.Service;$svc.Connect();$task=$svc.GetFolder('\').GetTask('BimeronStep8Probe')
 Assert-DurationIdle $task
 $cim=Get-ScheduledTask -TaskPath '\' -TaskName 'BimeronStep8Probe' -ErrorAction Stop
 if($cim.Triggers.Count){throw 'Unexpected triggers'}
 $facts=Get-ProbeRegistration $task
 $policies=@(Get-ExecutionPolicy -List|Select-Object Scope,ExecutionPolicy)
 if((Get-ExecutionPolicy -Scope MachinePolicy) -ne 'Undefined' -or (Get-ExecutionPolicy -Scope UserPolicy) -ne 'Undefined'){throw 'Managed policy changed'}
 $sddl=[Security.AccessControl.RawSecurityDescriptor]::new($facts.security);$binary=New-Object byte[] $sddl.BinaryLength;$sddl.GetBinaryForm($binary,0)
 return [ordered]@{registration=$facts;settings=(Get-DurationSettings $cim.Settings);comDuration=$task.Definition.Settings.ExecutionTimeLimit;cimDuration=$cim.Settings.ExecutionTimeLimit;securityBinary=[Convert]::ToBase64String($binary);wrapperSHA256=(Get-ProbeFileSHA256 'C:/BimeronStep8/probe.ps1');policies=$policies;taskReady=$true;instances=0;utc=[DateTime]::UtcNow.ToString('o')}
}
function Assert-DurationSnapshot($Original,$Current,[string]$Duration) {
 [DurationXml]::EqualExceptDuration($Original.registration.xml,$Current.registration.xml,$Duration)
 foreach($key in @('path','security')){if($Original.registration.$key -cne $Current.registration.$key){throw "Registration $key changed"}}
 foreach($key in @('action','principal')){if(($Original.registration.$key|ConvertTo-Json -Depth 12 -Compress) -cne ($Current.registration.$key|ConvertTo-Json -Depth 12 -Compress)){throw "Registration $key changed"}}
 if($Current.comDuration -cne $Duration -or $Current.cimDuration -cne $Duration -or $Current.wrapperSHA256 -cne $Original.wrapperSHA256 -or $Current.securityBinary -cne $Original.securityBinary -or !$Current.taskReady -or $Current.instances -ne 0){throw 'Duration/security/wrapper/idle changed'}
 if(($Original.policies|ConvertTo-Json -Compress) -cne ($Current.policies|ConvertTo-Json -Compress)){throw 'Policies changed'}
 $settings=$Current.settings|ConvertFrom-Json
 $entry=@($settings.properties|Where-Object {$_.name -ceq 'ExecutionTimeLimit'})
 if($entry.Count -ne 1 -or $entry[0].value -cne $Duration){throw 'CIM duration missing/wrong'}
 $entry[0].value='PT3M'
 if(($settings|ConvertTo-Json -Depth 30 -Compress) -cne (($Original.settings|ConvertFrom-Json)|ConvertTo-Json -Depth 30 -Compress)){throw 'Other CIM setting changed'}
}
function Write-DurationJson([string]$Path,$Value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 35))
 $f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}
