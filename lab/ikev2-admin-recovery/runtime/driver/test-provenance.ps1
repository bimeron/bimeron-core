param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop';. "$PSScriptRoot/provenance.ps1"
New-Item -ItemType Directory $Output -ErrorAction Stop|Out-Null
if(!(Test-ProbeCimCreation ([DateTime]::Parse('2026-11-03T00:00:00.1234560Z')) '2026-11-03T00:00:00.1234567Z')){throw 'CIM precision comparison failed'}
if(Test-ProbeCimCreation ([DateTime]::Parse('2026-11-03T00:00:00.1234570Z')) '2026-11-03T00:00:00.1234567Z'){throw 'Changed CIM creation accepted'}
$registration=[pscustomobject][ordered]@{xml='<task/>';path='\BimeronStep8Probe';security='D:fixture';action=@([pscustomobject]@{Execute='cmd.exe';Arguments='/c fixture';WorkingDirectory=$null});principal=[pscustomobject]@{sid='S-1-test';level=0;logon=1;token=2;privileges=@()}}
$parent=@{pid=100;start='2026-11-03T00:00:01Z';path='C:\Windows\System32\cmd.exe';sha256='cmdhash';sid='S-1-test';integrity='S-1-16-8192';elevated=$false;alive=$true}
$producer=@{pid=101;parent=100;start='2026-11-03T00:00:02Z';path='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';sha256='pshash';sid='S-1-test';integrity='S-1-16-8192';elevated=$false;alive=$true}
$fixture=@{expected=@{registration=$registration;images=@{cmd=@{path=$parent.path;sha256='cmdhash'};powershell=@{path=$producer.path;sha256='pshash'}}};registration=$registration;launch=@{guid='instance-a';engine=100;bookmark=20;before='2026-11-03T00:00:00Z'};instance=@{guid='instance-a';engine=100;path='\BimeronStep8Probe';state=4};event=@{guid='instance-a';engine=100;task='\BimeronStep8Probe';action='cmd.exe';record=21};parent=$parent;producer=$producer;pinned=@{parent=$parent;producer=$producer}}
$raw=$fixture|ConvertTo-Json -Depth 12
function Check($f){Assert-ProbeProvenance $f.expected $f.registration $f.launch $f.instance $f.event $f.parent $f.producer $f.pinned}
Check ($raw|ConvertFrom-Json)
$results=@()
foreach($case in @('action','principal','image','unrelated-parent','instance','event-instance','reused-process','exited','registration','security','missing','old-event','engine-changed','arguments')){
 $f=$raw|ConvertFrom-Json
 switch($case){
  action{$f.expected.registration.action[0].Arguments='/c unexpected'}
  principal{$f.expected.registration.principal.sid='wrong'}
  image{$f.expected.images.powershell.sha256='wrong'}
  unrelated-parent{$f.parent.pid=999;$f.producer.parent=999}
  instance{$f.instance.guid='other'}
  event-instance{$f.event.guid='other'}
  reused-process{$f.producer.start='2026-11-03T00:00:03Z'}
  exited{$f.parent.alive=$false}
  registration{$f.registration.xml='<changed/>'}
  security{$f.registration.security='changed'}
  missing{$f.event=$null}
  old-event{$f.event.record=19}
  engine-changed{$f.instance.engine=999}
  arguments{$f.producer|Add-Member arguments @('unexpected')}
 }
 $errorText=$null;try{Check $f}catch{$errorText=$_.Exception.Message}
 if(!$errorText){throw "Negative accepted: $case"};$results+=@{case=$case;refused=$errorText}
}
$results|ConvertTo-Json|Set-Content (Join-Path $Output 'results.json')
"PASS positive + $($results.Count) provenance negatives"
