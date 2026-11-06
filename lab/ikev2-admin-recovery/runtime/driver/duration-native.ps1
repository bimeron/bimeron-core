param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$Nonce)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/file-sha256.ps1"
$out=Join-Path $PSScriptRoot ("duration-validation-"+$Nonce.Substring(0,16));New-Item -ItemType Directory $out -ErrorAction Stop|Out-Null
[IO.File]::WriteAllText("$out/nonce.txt",$Nonce)
$vm=Get-VM -Id '<LAB_VM_ID>' -ErrorAction Stop
if($vm.State -ne 'Running'){throw 'Designated VM not Running'}
$vm|Select-Object Id,Name,State|ConvertTo-Json|Set-Content "$out/vm.json"
$cred=Import-Clixml (Join-Path $env:LOCALAPPDATA 'Bimeron/ikev2-clean-lab.credential.xml')
$session=New-PSSession -VMId '<LAB_VM_ID>' -Credential $cred
$root="C:/BimeronStep10Duration/$Nonce"
try{
 Invoke-Command -Session $session -ArgumentList $root -ScriptBlock {param($root)
  if($env:COMPUTERNAME -cne '<LAB_GUEST_NAME>'){throw 'Guest binding'}
  New-Item -ItemType Directory $root -ErrorAction Stop|Out-Null
 }
 $files=@('DurationXml.cs','duration-common.ps1','duration-step.ps1','duration-wait.ps1','duration-controller.ps1','file-sha256.ps1','provenance.ps1')
 $pins=@(foreach($name in $files){
  Copy-Item -ToSession $session -LiteralPath "$PSScriptRoot/$name" -Destination "$root/$name"
  @{name=$name;sha256=(Get-ProbeFileSHA256 "$PSScriptRoot/$name")}
 })
 Copy-Item -ToSession $session -LiteralPath "$PSScriptRoot/prep-3216a742d4cccd4f/guest/expected.json" -Destination "$root/accepted-3216.json"
 Copy-Item -ToSession $session -LiteralPath "$PSScriptRoot/prep-3216a742d4cccd4f/guest/policy-before.json" -Destination "$root/accepted-policy.json"
 Copy-Item -ToSession $session -LiteralPath "<LAB_STEP9_ABI_ROOT>/run-03402f6d17957406425a2308dcfb9b11006c798ddee8bddc65dbd507ccf3272d/expected.json" -Destination "$root/owned-guids.json"
 $pins+=@{name='accepted-3216.json';sha256=(Get-ProbeFileSHA256 "$PSScriptRoot/prep-3216a742d4cccd4f/guest/expected.json")}
 $pins+=@{name='accepted-policy.json';sha256=(Get-ProbeFileSHA256 "$PSScriptRoot/prep-3216a742d4cccd4f/guest/policy-before.json")}
 $pins+=@{name='owned-guids.json';sha256=(Get-ProbeFileSHA256 "<LAB_STEP9_ABI_ROOT>/run-03402f6d17957406425a2308dcfb9b11006c798ddee8bddc65dbd507ccf3272d/expected.json")}
 $pins|ConvertTo-Json|Set-Content "$out/deployed-pins.json"
 Invoke-Command -Session $session -ArgumentList $root,$pins -ScriptBlock {param($root,$pins)
  foreach($pin in $pins){if((Get-FileHash "$root/$($pin.name)").Hash -ine $pin.sha256){throw 'Deployed duration procedure/baseline hash mismatch'}}
  $shell='C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
  $p=Start-Process $shell -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"$root/duration-controller.ps1",'-Root',$root) -RedirectStandardOutput "$root/controller.stdout" -RedirectStandardError "$root/controller.stderr"
  $handle=$p.Handle
  @{pid=$p.Id;startFiletime=$p.StartTime.ToFileTimeUtc();exe=$p.MainModule.FileName}|ConvertTo-Json|Set-Content "$root/controller-identity.json"
  if(!$p.WaitForExit(120000)){throw 'Controller outer timeout: UNCERTAIN; no kill or cancellation'}
  $p.ExitCode|Set-Content "$root/controller-exit.txt"
  if($null -eq $p.ExitCode -or $p.ExitCode -ne 0){throw 'Duration validation refused; inspect preserved readbacks'}
 }
}catch{$_|Out-String|Set-Content "$out/host-error.txt";throw}finally{
 try{Copy-Item -FromSession $session -LiteralPath $root -Destination "$out/guest" -Recurse -ErrorAction Stop}
 finally{Remove-PSSession $session}
}
