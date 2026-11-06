# Guest SCM helpers, loaded into the single retained administrative session.
function Get-StockCanonicalServiceName([string]$Name) {
 $serviceMatches=@(@('RasMan','EapHost','IKEEXT','BFE','PolicyAgent','RemoteAccess','dot3svc','XboxNetApiSvc') | Where-Object {$_ -ieq $Name})
 if($serviceMatches.Count -eq 1){return $serviceMatches[0]}
 return $Name
}
function Get-StockServiceSnapshot {
 $names=@('RasMan','EapHost','IKEEXT','BFE','PolicyAgent','RemoteAccess','dot3svc','XboxNetApiSvc')
 $all=@(Get-CimInstance Win32_Service -ErrorAction Stop)
 @($names | ForEach-Object {
  $name=$_;$s=@($all | Where-Object Name -IEQ $name)
  if($s.Count -ne 1){throw 'HOLD: missing exact service'}
  $c=Get-Service -Name $name -ErrorAction Stop
  @{name=$name;state=[string]$s[0].State;startMode=[string]$s[0].StartMode;path=[string]$s[0].PathName;account=[string]$s[0].StartName;exitCode=[uint32]$s[0].ExitCode;serviceSpecificExitCode=[uint32]$s[0].ServiceSpecificExitCode;pid=[uint32]$s[0].ProcessId;canStop=[bool]$c.CanStop;dependents=@($c.DependentServices | ForEach-Object {@{name=(Get-StockCanonicalServiceName $_.Name);state=[string]$_.Status}});cohosts=@($all | Where-Object {$s[0].ProcessId -ne 0 -and $_.ProcessId -eq $s[0].ProcessId} | Sort-Object Name | ForEach-Object {@{name=(Get-StockCanonicalServiceName $_.Name);state=$_.State;startMode=$_.StartMode;path=$_.PathName;account=$_.StartName}})}
 })
}
function Stop-StockService([string]$Name,$Baseline) {
 if($Name -cnotin @('RasMan','EapHost','IKEEXT')){throw 'HOLD: service outside scope'}
 return Invoke-StockGuestStep ('scm-stop-'+$Name) {
 $before=@(Get-StockServiceSnapshot | Where-Object name -CEQ $Name)[0]
 foreach($key in @('name','startMode','path','account')){if($before[$key] -cne $Baseline[$key]){throw 'HOLD: service identity/baseline changed'}}
 if(@($before.dependents | Where-Object state -CNE 'Stopped').Count){throw 'HOLD: active dependent'}
 $timer=[Diagnostics.Stopwatch]::StartNew()
 if($before.state -ceq 'Running'){
  if(!$before.canStop){throw 'HOLD: stop unsupported'}
  # ServiceController.Stop sends SCM control; it does not stop dependencies.
  $controller=Open-StockServiceController $Name
  try {$controller.Stop()} finally {$controller.Dispose()}
 } elseif($before.state -cne 'Stopped'){throw 'HOLD: transitional service state'}
 return @{before=$before;submittedUtc=[DateTime]::UtcNow.ToString('o')}
 } {param($intent)
 $before=$intent.before;$timer=[Diagnostics.Stopwatch]::StartNew()
 do {
  $after=@(Get-StockServiceSnapshot | Where-Object name -CEQ $Name)[0]
  if($after.state -ceq 'Stopped'){break}
  Start-Sleep -Milliseconds 100
 } while($timer.Elapsed.TotalSeconds -lt 30)
 if($after.state -cne 'Stopped' -or $after.exitCode -ne 0 -or $after.serviceSpecificExitCode -ne 0 -or $after.pid -ne 0){throw 'HOLD: normal STOPPED unproven'}
 foreach($key in @('name','startMode','path','account')){if($after[$key] -cne $Baseline[$key]){throw 'HOLD: stopped identity changed'}}
 return @{before=$before;after=$after;elapsedMilliseconds=$timer.ElapsedMilliseconds;submittedUtc=$intent.submittedUtc}
 }
}
function Get-StockSaCounts {
 # Reader failure throws; it is never converted to a zero count.
 $main=@(Get-NetIPsecMainModeSA -ErrorAction Stop)
 $quick=@(Get-NetIPsecQuickModeSA -ErrorAction Stop)
 return @{main=$main.Count;quick=$quick.Count;reader='NetSecurity';success=$true}
}

function Open-StockServiceController([string]$Name) {return [ServiceProcess.ServiceController]::new($Name)}
