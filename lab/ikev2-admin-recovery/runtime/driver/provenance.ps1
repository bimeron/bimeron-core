function Test-ProbeCimCreation {
 param([DateTime]$CimTime,[string]$PinnedTime)
 # CIM_DATETIME exposes microseconds; retained native handle keeps full FILETIME.
 $ticks=[DateTime]::Parse($PinnedTime).ToUniversalTime().Ticks
 return ($CimTime.ToUniversalTime().Ticks -eq ($ticks-($ticks % 10)))
}
function Get-ProbeRegistration {
 param($RegisteredTask)
 $t=Get-ScheduledTask -TaskName BimeronStep8Probe
 $sid=([Security.Principal.NTAccount]::new($env:COMPUTERNAME,$t.Principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value
 [pscustomobject][ordered]@{xml=$RegisteredTask.Xml;path=$RegisteredTask.Path;security=$RegisteredTask.GetSecurityDescriptor(7);action=@($t.Actions|Select-Object Execute,Arguments,WorkingDirectory);principal=[pscustomobject][ordered]@{sid=$sid;logon=[int]$t.Principal.LogonType;level=[int]$t.Principal.RunLevel;token=[int]$t.Principal.ProcessTokenSidType;privileges=@($t.Principal.RequiredPrivilege|Where-Object {$null -ne $_})}}
}
function Assert-ProbeRegistration {
 param($Expected,$Actual)
 foreach($key in @('xml','path','security')){if($Expected.$key -cne $Actual.$key){throw "Expected registration $key mismatch"}}
 foreach($key in @('action','principal')){if(($Expected.$key|ConvertTo-Json -Depth 8 -Compress) -cne ($Actual.$key|ConvertTo-Json -Depth 8 -Compress)){throw "Expected registration $key mismatch"}}
}
function Assert-ProbeProvenance {
 param($Expected,$Registration,$Launch,$Instance,$Event,$Parent,$Producer,$Pinned)
 Assert-ProbeRegistration $Expected.registration $Registration
 if(!$Instance -or !$Event -or !$Parent -or !$Producer){throw 'Missing authoritative provenance observation'}
 if($Instance.guid -ne $Launch.guid -or $Instance.path -cne $Expected.registration.path -or $Instance.state -ne 4 -or $Instance.engine -ne $Launch.engine){throw 'Scheduler instance changed/not running'}
 if($Event.guid -ne $Launch.guid -or $Event.engine -ne $Launch.engine -or $Event.task -cne $Expected.registration.path -or $Event.action -cne $Expected.registration.action[0].Execute -or $Event.record -le $Launch.bookmark){throw 'Scheduler event200 mismatch'}
 if($Parent.pid -ne $Launch.engine -or $Producer.parent -ne $Parent.pid){throw 'Producer is not child of authoritative task action process'}
 foreach($pair in @(@($Parent,'cmd'),@($Producer,'powershell'))){
  $p=$pair[0];$image=$Expected.images.($pair[1])
  if(!$p.alive -or $p.path -ine $image.path -or $p.sha256 -ine $image.sha256){throw 'Expected image/liveness mismatch'}
  if($p.sid -ne $Expected.registration.principal.sid -or $p.elevated -or $p.integrity -ne 'S-1-16-8192'){throw 'Expected ordinary token mismatch'}
  if(($p.arguments|ConvertTo-Json -Compress) -cne ($image.arguments|ConvertTo-Json -Compress)){throw 'Expected process arguments mismatch'}
 }
 if([DateTime]::Parse($Parent.start).ToUniversalTime() -lt [DateTime]::Parse($Launch.before).ToUniversalTime() -or [DateTime]::Parse($Producer.start).ToUniversalTime() -lt [DateTime]::Parse($Parent.start).ToUniversalTime()){throw 'Process creation ordering mismatch'}
 if($Pinned){foreach($key in @('pid','start','path','sid','sha256')){if($Parent.$key -cne $Pinned.parent.$key -or $Producer.$key -cne $Pinned.producer.$key){throw 'Pinned process identity changed/reused'}}}
}
