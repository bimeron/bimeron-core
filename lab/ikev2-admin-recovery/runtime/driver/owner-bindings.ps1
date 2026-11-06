# Supervisor binding helpers. Import is inert; all reads use the trusted root.
function Get-OwnerProofRef([string]$Name){
 $b=Read-OwnerBytes "$script:root/transport/proofs/$Name" -Root $script:root -MaxBytes 67108864
 @{name=$Name;sha256=(Get-OwnerSHA256 $b);length=$b.Length}
}
function Assert-OwnerSame($A,$B){
 if(($A|ConvertTo-Json -Depth 16 -Compress) -cne ($B|ConvertTo-Json -Depth 16 -Compress)){throw 'Binding mismatch'}
}
function Assert-OwnerBinding($B){
 Assert-OwnerFields $B @('SHA256','Nonce','PolicySHA256')
 if($B.SHA256 -cne $script:config.ownerSHA256 -or $B.Nonce -cne $script:nonce -or $B.PolicySHA256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Native binding mismatch'}
}
function Get-OwnerInstanceFacts {
 $token=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=[Security.Principal.WindowsPrincipal]::new($token);$process=[Diagnostics.Process]::GetCurrentProcess()
 @{principalSid=$token.User.Value;elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);sessionId=$process.SessionId;pid=$PID;creationFileTime=[string]$process.StartTime.ToUniversalTime().ToFileTimeUtc()}
}
function Get-OwnerRegisteredTask($Name){$svc=New-Object -ComObject Schedule.Service;$svc.Connect();$svc.GetFolder('\').GetTask($Name)}
function Initialize-OwnerInstance($Root,$Config,$ConfigHash){
 Assert-OwnerFields $Config @('schema','nonce','vm','guest','principalName','principalSid','taskName','ownerSHA256','supervisorSHA256','ledgerSHA256')
 if($Config.schema -cne 'full300-owner-config-v1' -or $Config.nonce -cne $script:nonce -or $Config.guest -cne $env:COMPUTERNAME -or $Config.taskName -cne "BimeronFull300Owner-$script:nonce"){throw 'Supervisor configuration mismatch'}
 $facts=Get-OwnerInstanceFacts
 if($facts.principalSid -cne $Config.principalSid -or !$facts.elevated -or $facts.sessionId -le 0){throw 'Interactive elevated principal required'}
 $ledgerBytes=Read-OwnerBytes "$Root/deployment.json" -Root $Root
 if((Get-OwnerSHA256 $ledgerBytes) -cne $Config.ledgerSHA256){throw 'Deployment ledger mismatch'}
 $ledger=Assert-StrictOwnerJson $ledgerBytes;Assert-OwnerFields $ledger @('files')
 foreach($f in $ledger.files){if($f.name -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$' -or $f.name.Contains('..')){throw 'Invalid deployment name'};$b=Read-OwnerBytes "$Root/$($f.name)" -Root $Root -MaxBytes 67108864;if($b.Length -ne $f.length -or (Get-OwnerSHA256 $b) -cne $f.sha256){throw 'Deployment changed'}}
 foreach($pair in @(@('full300-owner.exe',$Config.ownerSHA256),@('owner-supervisor.ps1',$Config.supervisorSHA256))){if((Get-OwnerSHA256 (Read-OwnerBytes "$Root/$($pair[0])" -Root $Root -MaxBytes 67108864)) -cne $pair[1]){throw 'Executable binding changed'}}
 $task=Get-OwnerRegisteredTask $Config.taskName
 $baseline=Assert-StrictOwnerJson (Read-OwnerBytes "$Root/transport/task-registration.json" -Root $Root)
 if($task.Xml -cne $baseline.xml -or $task.GetSecurityDescriptor(7) -cne $baseline.sddl){throw 'Supervisor registration changed'}
 if(!$baseline.fileSddl -or (Get-OwnerTaskFileSddl $Config.taskName) -cne $baseline.fileSddl){throw 'Supervisor task file ACL changed or baseline missing'}
 $d=$task.Definition
 if((Get-OwnerPrincipalSid $d.Principal.UserId) -cne $Config.principalSid -or $d.Principal.RunLevel -ne 1 -or $d.Principal.LogonType -ne 3 -or $d.Triggers.Count -ne 0 -or $d.Actions.Count -ne 1 -or $d.Settings.RestartCount -ne 0 -or $d.Settings.ExecutionTimeLimit -cne 'PT0S' -or $d.Settings.AllowHardTerminate){throw 'Supervisor task mismatch'}
 $once="$Root/transport/proofs/supervisor-once.json"
 if([IO.File]::Exists($once)){throw 'Original supervisor already exists'}
 Write-OwnerDocument $once @{schema='full300-supervisor-once-v1';nonce=$script:nonce;configSHA256=$ConfigHash;instanceId=[guid]::NewGuid().ToString();pid=$facts.pid;creationFileTime=$facts.creationFileTime;principalSid=$facts.principalSid;sessionId=$facts.sessionId;elevated=$facts.elevated}
}
function Save-OwnerNativeSnapshots($Root,$Sequence,$Once){
 $refs=@();$status=$null;$events=$null
 foreach($name in @('gate-status.json','events.jsonl','gate-request.json','rules-bootstrap.json','guids.json','bfe-bootstrap.xml','owner-once.json')){
  if(![IO.File]::Exists("$Root/$name")){continue}
  $full=Assert-OwnerFilePath "$Root/$name" $Root
  $stream=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
  try{$length=$stream.Length;if($length -gt 67108864){throw 'Native snapshot bound'};$b=[byte[]]::new([int]$length);$offset=0;while($offset -lt $length){$count=$stream.Read($b,$offset,$length-$offset);if(!$count){throw 'Short native snapshot'};$offset+=$count}}finally{$stream.Dispose()}
  if($name -ceq 'events.jsonl'){$end=[Array]::LastIndexOf($b,[byte]10);if($end -lt 0){$b=[byte[]]@()}else{$b=[byte[]]$b[0..$end]}}
  $ref=@{name="$Sequence-$name";length=$b.Length;sha256=(Get-OwnerSHA256 $b)}
  Publish-OwnerBytesOnce "$Root/transport/samples/$($ref.name)" $b -Root $Root -MaxBytes 67108864
  $refs+=$ref;if($name -ceq 'gate-status.json'){$status=$ref};if($name -ceq 'events.jsonl'){$events=$ref}
 }
 @{refs=$refs;nativeStatus=$status;nativeEvents=$events}
}
function Assert-OwnerLaunchBinding($AdmissionBytes,$PinsBytes,$EvidenceBytes,$Config){
 $a=Assert-StrictOwnerJson $AdmissionBytes;$pins=@(Assert-StrictOwnerJson $PinsBytes);$e=Assert-StrictOwnerJson $EvidenceBytes
 Assert-OwnerFields $a @('SHA256','VM','Peer','Profile','Nonce','ProducerPinSHA256')
 Assert-OwnerFields $e @('schema','nonce','configSHA256','producerPin','readiness','readerAdmissions','controlsJournal','controlsCapture','controlsAssessment','nativePinsSHA256','ownerSHA256')
 if($e.schema -cne 'full300-launch-evidence-v1' -or $e.nonce -cne $script:nonce -or $e.configSHA256 -cne $script:configHash -or $e.ownerSHA256 -cne $Config.ownerSHA256 -or $a.SHA256 -cne $Config.ownerSHA256 -or $a.Nonce -cne $script:nonce -or $a.VM -cne $Config.vm -or $a.Peer -cne '<LAB_PUBLIC_IP>' -or $a.Profile -cne 'Bimeron Step8' -or $a.ProducerPinSHA256 -cne (Get-OwnerSHA256 $PinsBytes) -or $e.nativePinsSHA256 -cne $a.ProducerPinSHA256){throw 'Admission binding mismatch'}
 foreach($n in @('producerPin','readiness','readerAdmissions','controlsJournal','controlsCapture','controlsAssessment')){$null=Read-OwnerProof $e.$n}
 $original=Read-OwnerProofJson $e.producerPin
 if($pins.Count -ne 2 -or @($original.process).Count -ne 2 -or $pins[0].PID -eq $pins[1].PID){throw 'Two original pins required'}
 foreach($p in $pins){Assert-OwnerFields $p @('PID','CreationUTC','Path','SHA256');$match=@($original.process|Where-Object pid -EQ $p.PID);if($match.Count -ne 1 -or [DateTime]::Parse($p.CreationUTC).ToUniversalTime() -ne [DateTime]::Parse($match[0].start).ToUniversalTime() -or $p.Path -cne $match[0].path -or $p.SHA256 -cne $match[0].sha256.ToLowerInvariant()){throw 'Native pins differ from inspector'}}
 $assessment=Read-OwnerProofJson $e.controlsAssessment
 if($assessment.schema -cne 'full300-admission-v1' -or $assessment.admitted -ne $true){throw 'Host admission refused'}
}
function Assert-OwnerStartBinding($RequestBytes,$PolicyBytes,$BarrierBytes,$Config){
 $r=Assert-StrictOwnerJson $RequestBytes;$p=Assert-StrictOwnerJson $PolicyBytes;$b=Assert-StrictOwnerJson $BarrierBytes
 Assert-OwnerFields $r @('SHA256','Nonce','PolicySHA256','BFESHA256','BarrierSHA256')
 Assert-OwnerFields $p @('schema','nonce','configSHA256','binding','bfe','rules','guids','gate','assessment')
 Assert-OwnerFields $b @('schema','nonce','configSHA256','binding','metadata','journal','producerPin')
 foreach($v in @($p,$b)){if($v.nonce -cne $script:nonce -or $v.configSHA256 -cne $script:configHash){throw 'Start wrapper mismatch'};Assert-OwnerBinding $v.binding;foreach($k in @('SHA256','Nonce','PolicySHA256')){if($r.$k -cne $v.binding.$k){throw 'Start request binding mismatch'}}}
 if($p.schema -cne 'full300-policy-evidence-v1' -or $b.schema -cne 'full300-barrier-evidence-v1'){throw 'Start wrapper schema'}
 foreach($n in @('bfe','rules','guids','gate','assessment')){$null=Read-OwnerProof $p.$n}
 foreach($n in @('metadata','journal','producerPin')){$null=Read-OwnerProof $b.$n}
 $hash=Get-OwnerSHA256 ([Text.Encoding]::UTF8.GetBytes($p.rules.sha256+"`n"+$p.guids.sha256))
 $gate=Read-OwnerProofJson $p.gate;Assert-OwnerBinding $gate
 foreach($k in @('SHA256','Nonce','PolicySHA256')){if($gate.$k -cne $r.$k){throw 'Gate mismatch'}}
 if($hash -cne $r.PolicySHA256 -or $r.BFESHA256 -cne $p.bfe.sha256 -or $r.BarrierSHA256 -cne $b.metadata.sha256 -or (Read-OwnerProofJson $p.assessment).status -cne 'PASS'){throw 'Policy assessment mismatch'}
 $m=Read-OwnerProofJson $b.metadata;Assert-OwnerFields $m @('nonce','probeSHA256','gateSHA256','sequence','round')
 if($m.nonce -cne $script:nonce -or $m.probeSHA256 -cne $b.journal.sha256 -or $m.gateSHA256 -cne $p.gate.sha256 -or $m.sequence -isnot [int] -or $m.sequence -lt 0 -or $m.round -isnot [int] -or $m.round -lt 0){throw 'Barrier mismatch'}
}
function Assert-OwnerCleanupBinding($Request,$Drain,$Proofs,$Readback,$Expected,$Launch,$Registration){
 $r=Assert-StrictOwnerJson $Request;Assert-OwnerFields $r @('SHA256','Nonce','PolicySHA256','Failure','ReaderClosureSHA256','TaskClosureSHA256');Assert-OwnerBinding $Drain.binding
 foreach($k in @('SHA256','Nonce','PolicySHA256')){if($r.$k -cne $Drain.binding.$k){throw 'Cleanup binding mismatch'}}
 if($r.Failure -isnot [bool] -or $r.ReaderClosureSHA256 -cne $Drain.readerClosures.sha256 -or $r.TaskClosureSHA256 -cne $Drain.taskClosure.sha256){throw 'Cleanup digests mismatch'}
 $e=Assert-StrictOwnerJson $Expected;$l=Assert-StrictOwnerJson $Launch;$reg=Assert-StrictOwnerJson $Registration
 Assert-OwnerSame $e.registration $reg
 if($l.nonce -cne $script:nonce -or $l.guid -cne $Readback.launchInstanceGuid){throw 'Task launch mismatch'}
}
