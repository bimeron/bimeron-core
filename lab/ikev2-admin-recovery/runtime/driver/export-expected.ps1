param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][string]$Nonce,[switch]$SmokeOnly,[string]$FixtureRegistrationPath,[ValidateSet('PT3M','PT20M')][string]$TaskDuration='PT3M')
$ErrorActionPreference='Stop';. "$PSScriptRoot/file-sha256.ps1";. "$PSScriptRoot/provenance.ps1";Add-Type -Path "$PSScriptRoot/ProcessPin.cs";. "$PSScriptRoot/expected-schema.ps1"
if($FixtureRegistrationPath){
 if(!$SmokeOnly){throw 'Local fixture requires smoke mode; never launch'}
 $facts=Get-Content -Raw $FixtureRegistrationPath|ConvertFrom-Json
}else{
 $svc=New-Object -ComObject Schedule.Service;$svc.Connect();$task=$svc.GetFolder('\').GetTask('BimeronStep8Probe')
 $facts=Get-ProbeRegistration $task
}
$retained=Get-Content -Raw "$Root/retained-action.json"|ConvertFrom-Json
if(($facts.action|ConvertTo-Json -Compress) -cne ($retained|ConvertTo-Json -Compress)){throw 'Registered action differs from retained original'}
if($facts.principal.sid -ne '<LAB_GUEST_SID_1002>' -or $facts.principal.logon -ne 1 -or $facts.principal.level -ne 0 -or $facts.principal.token -ne 2 -or @($facts.principal.privileges|Where-Object {$_}).Count){throw 'Principal differs from independently inspected baseline'}
if(!$FixtureRegistrationPath -and ($task.Definition.Settings.ExecutionTimeLimit -ne $TaskDuration -or $task.Definition.Settings.MultipleInstances -ne 2 -or !$task.Definition.Settings.AllowDemandStart)){throw 'Unexpected task settings'}
$images=[ordered]@{
 cmd=@{path='C:\Windows\System32\cmd.exe';sha256='B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450';arguments=@([ProcessPin]::Arguments('cmd.exe '+$retained.Arguments))}
 powershell=@{path='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';sha256='9F914D42706FE215501044ACD85A32D58AAEF1419D404FDDFA5D3B48F66CCD9F';arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File','C:\BimeronStep8\probe.ps1','-Seconds','8')}
}
foreach($image in $images.Values){
 if((Get-ProbeFileSHA256 $image.path) -ine $image.sha256){throw 'Independent system image hash mismatch'}
 $sig=Get-AuthenticodeSignature $image.path
 if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike 'CN=Microsoft Windows,*'){throw 'System image signature not valid expected publisher'}
}
$inputs=Get-Content -Raw "$Root/planned-inputs.json"|ConvertFrom-Json
$names=@(Get-ProbeInputNames)
if($inputs -isnot [array] -or $inputs.Count -ne $names.Count){throw 'Planned inputs array/count'}
$canonical=@(for($i=0;$i -lt $names.Count;$i++){
 $item=$inputs[$i];$path=if($i -eq 0){'C:/BimeronStep8/probe.ps1'}else{"$Root/$($names[$i])"}
 if($item.path -cne $path -or $item.sha256 -cnotmatch '^[A-Fa-f0-9]{64}$'){throw 'Planned input path/hash'}
 [ordered]@{role=$names[$i];path=$path;sha256=[string]$item.sha256}
})
foreach($item in $canonical){$readPath=if($SmokeOnly -and $item.role -eq 'wrapper'){"$Root/planned-wrapper.ps1"}else{$item.path};if((Get-ProbeFileSHA256 $readPath) -ine $item.sha256){throw 'Deployed bytes differ from host planned inputs'}}
$expected=@{schemaVersion=1;nonce=$Nonce;registration=$facts;images=$images;inputs=$canonical;baseline='New independently inspected full XML, not historical full XML parity'}
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($expected|ConvertTo-Json -Depth 10))
$parsed=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json
Assert-ExpectedSchema $parsed $Nonce $Root
$name=if($SmokeOnly){'smoke-expected.json'}else{'expected.json'}
$f=[IO.File]::Open("$Root/$name",[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
[IO.File]::WriteAllText("$Root/registration-before.xml",$facts.xml,[Text.UTF8Encoding]::new($false))
