param([ValidatePattern('^[a-f0-9]{64}$')][string]$Nonce,[string]$Output)
$ErrorActionPreference='Stop'
$cred=Import-Clixml (Join-Path $env:LOCALAPPDATA 'Bimeron/ikev2-clean-lab.credential.xml')
$s=New-PSSession -VMId '<LAB_VM_ID>' -Credential $cred
try{
 foreach($name in @('gate-request.json','bfe-bootstrap.xml','rules-bootstrap.json')){
  $dest=Join-Path $Output $name;if(Test-Path $dest){throw 'Collector collision'}
  Copy-Item -FromSession $s -LiteralPath "C:/BimeronStep10ProbeNative/$name" -Destination $dest -ErrorAction Stop
 }
}finally{Remove-PSSession $s}
& "$PSScriptRoot/guest-read.ps1" -Mode snapshot -Nonce $Nonce -Output (Join-Path $Output 'probe.jsonl')
