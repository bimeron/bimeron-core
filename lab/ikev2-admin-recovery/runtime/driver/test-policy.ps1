param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop';New-Item -ItemType Directory $Output -ErrorAction Stop|Out-Null
$Output=(Resolve-Path $Output).Path
$fixture=Join-Path $Output 'fixture.ps1';[IO.File]::WriteAllText($fixture,'exit 23')
$p=Start-Process 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe' -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Restricted','-File',$fixture) -RedirectStandardError "$Output/restricted.txt"
$retainedHandle=$p.Handle
if(!$p.WaitForExit(10000)){throw 'Policy test timeout'};$blockedExit=$p.ExitCode
& 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe' -NoProfile -ExecutionPolicy Bypass -File $fixture
$explicitExit=$LASTEXITCODE
if($null -eq $blockedExit -or $blockedExit -eq 0 -or $explicitExit -ne 23){throw 'Process policy regression failed'}
@{restrictedExit=$blockedExit;explicitProcessExit=$explicitExit;policyMutation=$false}|ConvertTo-Json|Set-Content "$Output/result.json"
