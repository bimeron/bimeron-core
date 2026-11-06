param([string]$Nonce)
# Import is inert. Deployment supplies byte I/O and attestation functions described below.
function ConvertTo-OwnerBytes($Value) { return ,([Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 16 -Compress))) }
function Write-OwnerDocument($Path,$Value) { $b=ConvertTo-OwnerBytes $Value; Publish-OwnerBytesOnce $Path $b -Root $script:root; return (Get-OwnerSHA256 $b) }
function Wait-OwnerProcess($Process) { return $Process.WaitForExit(0) }
function Start-OwnerProcess { Start-Process -FilePath "$script:root/full300-owner.exe" -ArgumentList @('protect-only',$script:root) -WindowStyle Hidden -PassThru -RedirectStandardOutput "$script:root/owner.stdout" -RedirectStandardError "$script:root/owner.stderr" }
function Wait-OwnerPoll { Start-Sleep -Milliseconds 250 }
function Enter-OwnerHold($ErrorRecord) { $script:state='HOLD'; $script:diagnostic=[string]$ErrorRecord }
function Read-OwnerProof($Ref) {
    Assert-OwnerRefs $Ref
    $b=Read-OwnerBytes "$script:root/transport/proofs/$($Ref.name)" -Root $script:root -MaxBytes 67108864
    if ($b.Length -ne $Ref.length -or (Get-OwnerSHA256 $b) -cne $Ref.sha256) { throw 'Proof digest mismatch' }
    return ,$b
}
function Read-OwnerProofJson($Ref) { Assert-StrictOwnerJson (Read-OwnerProof $Ref) }
function Initialize-OwnerSupervisor([string]$RunNonce) {
    if ($RunNonce -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid nonce' }
    $script:root="C:/BimeronFull300/$RunNonce"; $script:nonce=$RunNonce
    $b=Read-OwnerBytes "$script:root/transport/config.json" -Root $script:root
    $script:config=Assert-StrictOwnerJson $b; $script:configHash=Get-OwnerSHA256 $b
    # This attestation must verify exact config, ledger, current token/session,
    # task XML/SDDL and exclusive once publication; never adopt an old instance.
    $script:onceHash=Initialize-OwnerInstance $script:root $script:config $script:configHash
    $script:owner=$null; $script:ownerHandle=$null; $script:identity=$null
    $script:launchAttempted=$false; $script:sealed=$false; $script:exitProof=$null
    $script:cleanupHash=$null; $script:state='READY'; $script:next=1
    $script:pending=$null; $script:relay=@{}; $script:diagnostic=$null
}
function Read-NextOwnerCommand([long]$Sequence) {
    $path=("$script:root/transport/commands/{0:D8}.json" -f $Sequence)
    $null=Assert-OwnerFilePath $path $script:root
    try { $b=Read-OwnerBytes $path -Root $script:root } catch {
        $cause=$_.Exception
        while($cause.InnerException){$cause=$cause.InnerException}
        if($cause -is [IO.FileNotFoundException]){return $null}
        throw
    }
    return @{bytes=$b;seq=$Sequence;hash=(Get-OwnerSHA256 $b)}
}
function Start-ExactNativeOwner($Command) {
    if ($script:state -cne 'READY' -or $script:sealed -or $script:launchAttempted) { throw 'Launch forbidden' }
    $a=Read-OwnerProof $Command.body.admission; $p=Read-OwnerProof $Command.body.producerPins
    $e=Read-OwnerProof $Command.body.admissionEvidence
    Assert-OwnerLaunchBinding $a $p $e $script:config
    Publish-OwnerBytesOnce "$script:root/admission.json" $a -Root $script:root
    Publish-OwnerBytesOnce "$script:root/producer-pin.json" $p -Root $script:root
    $script:launchAttempted=$true; $script:state='LAUNCHING'
    $script:intentHash=Write-OwnerDocument "$script:root/transport/launch-intent.json" @{nonce=$script:nonce;configSHA256=$script:configHash;commandSHA256=$script:commandHash}
    $script:owner=Start-OwnerProcess
    $script:ownerHandle=$script:owner.Handle
    $script:identity=@{pid=$script:owner.Id;creationFileTime=([string]$script:owner.StartTime.ToUniversalTime().ToFileTimeUtc());path=$script:owner.MainModule.FileName;sha256=$script:config.ownerSHA256}
    $script:state='OWNING'
}
function Get-RetainedOwnerSample {
    if (!$script:owner) { return $null }
    $s=@{pid=$script:identity.pid;creationFileTime=$script:identity.creationFileTime;path=$script:identity.path;sha256=$script:identity.sha256;handleState='unknown';exitCode=$null}
    try { if (Wait-OwnerProcess $script:owner) { $s.handleState='signalled'; $s.exitCode=$script:owner.ExitCode } else { $s.handleState='live' } } catch { Enter-OwnerHold $_ }
    return $s
}
function Publish-OwnerExit {
    if (!$script:owner -or !$script:identity -or !(Wait-OwnerProcess $script:owner)) { throw 'No retained exit proof' }
    $raw=Save-OwnerNativeSnapshots $script:root $script:next $script:onceHash
    $proof=@{schema='full300-owner-exit-v1';nonce=$script:nonce;configSHA256=$script:configHash;supervisorOnceSHA256=$script:onceHash;launchIntentSHA256=$script:intentHash;owner=$script:identity;waitResult='signalled';exitCode=$script:owner.ExitCode;exitUtc=$script:owner.ExitTime.ToUniversalTime().ToString('o');cleanupRequestSHA256=$script:cleanupHash;nativeStatus=$raw.nativeStatus;nativeEvents=$raw.nativeEvents}
    $script:exitProof=Write-OwnerDocument "$script:root/transport/proofs/owner-exit.json" $proof
    $script:state='EXIT_OBSERVED'
}
function Assert-OwnerDrain($Ref,$Request) {
    $d=Read-OwnerProofJson $Ref
    Assert-OwnerFields $d @('schema','nonce','configSHA256','binding','admissions','readerClosures','taskClosure','inspectorExit','inspectorFinal','producerPin','terminalJournal','stopRequest')
    if ($d.schema -cne 'full300-drain-v1' -or $d.nonce -cne $script:nonce -or $d.configSHA256 -cne $script:configHash) { throw 'Drain binding mismatch' }
    Assert-OwnerFields $d.binding @('SHA256','Nonce','PolicySHA256')
    $proofs=@{}
    foreach ($n in @('admissions','readerClosures','taskClosure','inspectorExit','inspectorFinal','producerPin','terminalJournal','stopRequest')) { if ($null -ne $d.$n) { $proofs[$n]=if($n -ceq 'terminalJournal'){Read-OwnerProof $d.$n}else{Read-OwnerProofJson $d.$n} } elseif ($n -ne 'stopRequest') { throw 'Missing drain evidence' } }
    $i=$proofs.inspectorExit
    Assert-OwnerFields $i @('schema','nonce','expectedSHA256','inspector','waitResult','exitCode','inspectorFinalSHA256')
    if ($i.schema -cne 'full300-inspector-exit-v1' -or $i.nonce -cne $script:nonce -or $i.waitResult -cne 'signalled' -or $i.inspectorFinalSHA256 -cne $d.inspectorFinal.sha256) { throw 'Inspector exit mismatch' }
    $t=$proofs.taskClosure
    Assert-OwnerFields $t @('schema','nonce','expected','launch','producerPin','inspectorFinal','inspectorExit','taskReadback','terminalJournal','stopRequest')
    if ($t.schema -cne 'full300-task-closure-v1' -or $t.nonce -cne $script:nonce) { throw 'Task closure mismatch' }
    foreach ($n in @('producerPin','inspectorFinal','inspectorExit','terminalJournal','stopRequest')) { if ((ConvertTo-Json $t.$n -Compress) -cne (ConvertTo-Json $d.$n -Compress)) { throw 'Manifest cross-reference mismatch' } }
    $r=Read-OwnerProofJson $t.taskReadback
    Assert-OwnerFields $r @('schema','nonce','path','registration','launchInstanceGuid','state','instanceGuids','lastTaskResult')
    if ($r.schema -cne 'full300-task-readback-v1' -or $r.nonce -cne $script:nonce -or $r.path -cne '\BimeronStep8Probe' -or $r.state -ne 3 -or @($r.instanceGuids).Count -ne 0) { throw 'Task not drained' }
    $expected=Read-OwnerProof $t.expected; $launch=Read-OwnerProof $t.launch; $registration=Read-OwnerProof $r.registration
    Assert-OwnerCleanupBinding $Request $d $proofs $r $expected $launch $registration
}
function Invoke-OwnerCommand($Packet) {
    if ($script:pending) { Complete-OwnerResponse; return }
    $script:commandHash=$Packet.hash; $refs=@(); $errorText=$null; $outcome='accepted'
    try {
        $c=Assert-OwnerEnvelope $Packet.bytes $script:nonce $script:configHash $Packet.seq
        switch -CaseSensitive ($c.op) {
            'launch' { Start-ExactNativeOwner $c; $refs=@((Save-OwnerNativeSnapshots $script:root $Packet.seq $script:onceHash).refs) }
            'sample' { $refs=@((Save-OwnerNativeSnapshots $script:root $Packet.seq $script:onceHash).refs) }
            { $_ -ceq 'start' -or $_ -ceq 'cleanup' } {
                if (!$script:owner -or $script:exitProof -or $script:relay.ContainsKey($c.op)) { throw 'Relay forbidden' }
                $request=Read-OwnerProof $c.body.request
                if ($c.op -ceq 'cleanup') { Assert-OwnerDrain $c.body.drain $request; $destination='cleanup-request.json' } else {
                    Assert-OwnerStartBinding $request (Read-OwnerProof $c.body.policyEvidence) (Read-OwnerProof $c.body.barrierEvidence) $script:config
                    $destination='start-observation.json'
                }
                $script:relay[$c.op]=$true
                $null=Write-OwnerDocument "$script:root/transport/$($c.op)-intent.json" @{commandSHA256=$Packet.hash;requestSHA256=$c.body.request.sha256}
                if ($c.op -ceq 'cleanup') { $script:cleanupHash=$c.body.request.sha256 }
                Publish-OwnerBytesOnce "$script:root/$destination" $request -Root $script:root
            }
            'seal-no-launch' {
                if ($script:state -cne 'READY' -or $script:launchAttempted) { throw 'Seal forbidden' }
                $script:sealed=$true; $script:state='SEALED_NO_LAUNCH'
                $script:sealHash=Write-OwnerDocument "$script:root/transport/proofs/no-launch.json" @{schema='full300-no-launch-v1';nonce=$script:nonce;configSHA256=$script:configHash;supervisorOnceSHA256=$script:onceHash;sealCommandSHA256=$Packet.hash;launchAttempted=$false;sealed=$true}
            }
            'exit-supervisor' {
                if ($script:exitProof) { $ref=$c.body.ownerExit; $hash=$script:exitProof; $reason='owner-signalled' } elseif ($script:sealed) { $ref=$c.body.noLaunch; $hash=$script:sealHash; $reason='sealed-no-launch' } else { throw 'Exit forbidden' }
                $null=Read-OwnerProof $ref
                if ($ref.sha256 -cne $hash) { throw 'Exit acknowledgement mismatch' }
                $null=Write-OwnerDocument "$script:root/transport/proofs/supervisor-exit-ready.json" @{schema='full300-supervisor-exit-v1';nonce=$script:nonce;configSHA256=$script:configHash;supervisorOnceSHA256=$script:onceHash;exitCommandSHA256=$Packet.hash;proofSHA256=$hash;reason=$reason}
                $script:state='EXIT_READY'
            }
        }
    } catch { $errorText=[string]$_; if ($script:launchAttempted) { Enter-OwnerHold $_; $outcome='hold' } else { $outcome='rejected' } }
    foreach($name in @('supervisor-once.json','owner-exit.json','no-launch.json','supervisor-exit-ready.json')){if([IO.File]::Exists("$script:root/transport/proofs/$name")){$refs+=Get-OwnerProofRef $name}}
    $sample=Get-RetainedOwnerSample
    $script:pending=ConvertTo-OwnerBytes @{schema='full300-owner-response-v1';nonce=$script:nonce;configSHA256=$script:configHash;seq=$Packet.seq;commandSHA256=$Packet.hash;outcome=$outcome;state=$script:state;owner=$sample;refs=$refs;error=$errorText}
    Complete-OwnerResponse
}
function Complete-OwnerResponse {
    Publish-OwnerBytesOnce ("$script:root/transport/responses/{0:D8}.json" -f $script:next) $script:pending -Root $script:root
    $script:pending=$null; $script:next++
}
function Invoke-OwnerForeground {
    while ($true) {
        try {
            if ($script:pending) { Complete-OwnerResponse } else {
                if ($script:owner -and !$script:exitProof -and (Wait-OwnerProcess $script:owner)) { Publish-OwnerExit }
                $packet=Read-NextOwnerCommand $script:next
                if ($packet) { Invoke-OwnerCommand $packet }
            }
            if ($script:state -ceq 'EXIT_READY' -and !$script:pending) { return }
        } catch { Enter-OwnerHold $_ }
        Wait-OwnerPoll
    }
}
if ($MyInvocation.InvocationName -ne '.') {
    . "$PSScriptRoot/owner-mailbox.ps1"
    . "$PSScriptRoot/owner-bindings.ps1"
    Initialize-OwnerSupervisor $Nonce
    Invoke-OwnerForeground
}
