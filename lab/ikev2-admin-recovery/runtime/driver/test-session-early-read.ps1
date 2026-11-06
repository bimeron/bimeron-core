$ErrorActionPreference='Stop'
# All remote, scheduler, clock, journal and native operations below are mocks.
Add-Type @'
using System;
using System.IO;
using System.Threading;
public static class OfflineStarts {
 public static int Active, Peak, Calls;
 public static void Start() { int n=Interlocked.Increment(ref Active); if(n>Peak) Peak=n; Interlocked.Increment(ref Calls); Thread.Sleep(250); Interlocked.Decrement(ref Active); }
}
public static class LabClock { public static string Read() { return "{}"; } }
public static class ProbeJournal {
 public static string LastReadOpenedUtc="", LastReadClosedUtc="";
 public static byte[] Snapshot(string p) { return File.ReadAllBytes(p); }
 public static byte[] Snapshot(string p,int hold) { return File.ReadAllBytes(p); }
}
'@
$protected=Join-Path $PSScriptRoot 'protected-guest.ps1'
$reader=Join-Path $PSScriptRoot 'guest-read.ps1'
foreach($path in @($protected,$reader)) {
 $tokens=$null;$errors=$null
 $null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($errors|Out-String)}
}
$worker={param($path,$gate,$fail)
 $ErrorActionPreference='Stop'
 function Import-Clixml { 'offline-credential' }
 function New-PSSession {param($VMId,$Credential) [OfflineStarts]::Start();if($fail){throw 'mock startup failure'};'offline-session'}
 function Invoke-Command {param($Session,$ScriptBlock)
  # Startup lock must already be released: verify from a different thread.
  $check=[powershell]::Create()
  try {
   $null=$check.AddScript('$m=[Threading.Mutex]::new($false,''Local\BimeronStep10-<LAB_VM_ID_PREFIX>-session-start'');try{$ok=$m.WaitOne(1500);if($ok){$m.ReleaseMutex()};$ok}finally{$m.Dispose()}')
   if(!($check.Invoke()[0])){throw 'Lock held during remote invocation'}
  }finally{$check.Dispose()}
  '<LAB_GUEST_NAME>'
 }
 function Remove-PSSession {}
 . $path
 $null=$gate.WaitOne(5000)
 Open-OwnerSession
}
function Start-OfflineWorker($gate,$fail=$false) {
 $ps=[powershell]::Create();$null=$ps.AddScript($worker.ToString()).AddArgument($protected).AddArgument($gate).AddArgument($fail)
 @{ps=$ps;handle=$ps.BeginInvoke()}
}
function Finish-OfflineWorker($job,$expectedError='') {
 try {
  try{$result=$job.ps.EndInvoke($job.handle)}catch{if(!$expectedError -or $_ -notmatch $expectedError){throw};return}
  if($expectedError){throw "Missing expected error: $expectedError"}
  if($job.ps.HadErrors -or $result[0] -cne 'offline-session'){throw 'Offline session result'}
 }finally{$job.ps.Dispose()}
}
$gate=[Threading.ManualResetEvent]::new($false)
try {
 $one=Start-OfflineWorker $gate;$two=Start-OfflineWorker $gate;$null=$gate.Set()
 Finish-OfflineWorker $one;Finish-OfflineWorker $two
 if([OfflineStarts]::Peak -ne 1 -or [OfflineStarts]::Calls -ne 2){throw 'Concurrent startup was not serialized'}
 $mutex=[Threading.Mutex]::new($false,'Local\BimeronStep10-<LAB_VM_ID_PREFIX>-session-start')
 $null=$mutex.WaitOne()
 try {
  $watch=[Diagnostics.Stopwatch]::StartNew();$blocked=Start-OfflineWorker $gate
  Finish-OfflineWorker $blocked 'Session setup mutex timeout'
  if($watch.Elapsed.TotalSeconds -gt 5 -or [OfflineStarts]::Calls -ne 2){throw 'Startup timeout bound or forbidden start'}
 }finally{$mutex.ReleaseMutex();$mutex.Dispose()}
 $failed=Start-OfflineWorker $gate $true;Finish-OfflineWorker $failed 'mock startup failure'
 $after=Start-OfflineWorker $gate;Finish-OfflineWorker $after
}finally{$gate.Dispose()}
'PASS: concurrent startup serialization, remote lock release, timeout, failure release'

# Execute the actual reader through its host entry point, with a temporary root
# substituted only inside the mocked remote transport. No VM session is created.
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('bimeron-read-offline-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path "$fixture/logs"
$nonce='a'*64
$task=[pscustomobject]@{State=3;LastTaskResult=0}
$task|Add-Member ScriptMethod GetInstances {param($flags) @()}
$folder=[pscustomobject]@{Task=$task}
$folder|Add-Member ScriptMethod GetTask {param($name) $this.Task}
$service=[pscustomobject]@{Folder=$folder}
$service|Add-Member ScriptMethod Connect {}
$service|Add-Member ScriptMethod GetFolder {param($name) $this.Folder}
function Import-Clixml {'offline-credential'}
function New-PSSession {param($VMId,$Credential) 'offline-session'}
function Remove-PSSession {}
function Add-Type {param($TypeDefinition)}
function New-Object {param($ComObject) if($ComObject -cne 'Schedule.Service'){throw 'Unexpected COM mock'};$service}
function netsh {param($a,$b,$c,$file) [IO.File]::WriteAllText($file.Substring(5),'<mock/>');$global:LASTEXITCODE=0}
function rasdial {'offline ras'}
function Invoke-Command {param($Session,$ArgumentList,$ScriptBlock)
 if($ArgumentList.Count -ne 7 -or ($ArgumentList[2] -eq 'integration' -and $ArgumentList[6] -cne [IO.File]::ReadAllText("$PSScriptRoot/provenance.ps1"))){throw 'Host provenance source not supplied'}
 $argsCopy=@($ArgumentList)
 $argsCopy[6]='function Get-ProbeRegistration($task) { @{xml="mock raw registration"} }'
 $body=$ScriptBlock.ToString().Replace('C:/BimeronStep10Probe/$nonce',$fixture.Replace('\','/'))
 & ([scriptblock]::Create($body)) @argsCopy
}
function Read-Offline($mode='integration') { & $reader -Mode $mode -Nonce $nonce | ConvertFrom-Json }
try {
 $envTemp=$env:TEMP;$env:TEMP=$fixture
 $raw=Read-Offline
 if($raw.probe -cne '' -or $null -ne $raw.readiness -or $raw.task.state -ne 3 -or $raw.task.instanceGuids.Count -ne 0){throw 'Missing-log raw state lost'}
 if($raw.files.PSObject.Properties.Name -cnotcontains 'registration.json'){throw 'Missing raw registration'}
 foreach($name in @('expected.json','inspector-final.json','inspector-exit-proof.json','launch.json','original-producer-pin.json')){
  if($name -cin $raw.files.PSObject.Properties.Name){throw "Synthetic proof: $name"}
 }
 [IO.File]::WriteAllBytes("$fixture/logs/probe-$nonce.jsonl",[byte[]]@())
 [IO.File]::WriteAllBytes("$fixture/logs/producer-health.jsonl",[byte[]]@())
 [IO.File]::WriteAllText("$fixture/logs/producer-pin.json",'{}')
 $raw=Read-Offline
 if($raw.probe -cne '' -or $null -ne $raw.readiness){throw 'Empty byte array lost'}
 $ready=Read-Offline 'ready'
 if($ready.ready -ne $false -or $ready.healthy -ne $false){throw 'Empty health must be pending'}
 foreach($bad in @("broken`n","`n","null`n")) {
  [IO.File]::WriteAllText("$fixture/logs/producer-health.jsonl",$bad)
  foreach($mode in @('ready','integration')) {
   $refused=$false;try{$null=Read-Offline $mode}catch{$refused=$true}
   if(!$refused){throw "Corrupt complete health accepted: $mode"}
  }
 }
 [IO.File]::WriteAllText("$fixture/logs/probe-$nonce.jsonl","raw journal`n")
 [IO.File]::WriteAllText("$fixture/logs/producer-health.jsonl",'{"ready":false}'+"`n")
 $raw=Read-Offline
 if([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw.probe)) -cne "raw journal`n"){throw 'Nonempty journal altered'}
 'PASS: missing/empty/nonempty journal, host provenance, raw partial state, pending versus corrupt health'
}finally{
 $env:TEMP=$envTemp
 # Only remove the explicitly created temporary fixture, never a run directory.
 if([IO.Path]::GetFileName($fixture) -notlike 'bimeron-read-offline-*'){throw 'Unsafe fixture cleanup'}
 Remove-Item -LiteralPath $fixture -Recurse -Force
}
