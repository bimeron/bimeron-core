param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop';New-Item -ItemType Directory $Output -ErrorAction Stop|Out-Null
$Output=(Resolve-Path $Output).Path
Add-Type -Path "$PSScriptRoot/ProcessPin.cs"
$fixture=Join-Path $Output 'finite.ps1';[IO.File]::WriteAllText($fixture,'Start-Sleep -Seconds 3; exit 23')
$child=Start-Process C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$fixture)
$handle=$child.Handle;$pin=[ProcessPin]::new($child.Id)
$input=[IO.File]::Open($fixture,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try{
 if(!$pin.Alive){throw 'Child not live'}
 $replacementRefused=$false;try{[IO.File]::WriteAllText($fixture,'exit 0')}catch [IO.IOException]{$replacementRefused=$true}
 if(!$replacementRefused){throw 'Pinned input replace accepted'}
 if(!$child.WaitForExit(7000)){throw 'Finite child timeout'}
 if($pin.Alive -or $child.ExitCode -ne 23){throw 'Exit not detected/propagated'}
 @{pid=$pin.Pid;start=$pin.Start;path=$pin.Path;exit=$child.ExitCode;aliveAfterExit=$pin.Alive;inputReplacementRefused=$replacementRefused}|ConvertTo-Json|Set-Content "$Output/result.json"
}finally{$input.Dispose();$pin.Dispose()}
