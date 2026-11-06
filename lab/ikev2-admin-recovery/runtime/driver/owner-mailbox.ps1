# Byte-oriented owner transport primitives. Import performs no external operations.
function Get-OwnerPrincipalSid([string]$UserId) {
    if ([string]::IsNullOrWhiteSpace($UserId)) { throw 'Missing task principal' }
    if ($UserId -cmatch '^S-1-[0-9-]+$') { return ([Security.Principal.SecurityIdentifier]::new($UserId)).Value }
    $account=if($UserId.Contains('\')){[Security.Principal.NTAccount]::new($UserId)}else{[Security.Principal.NTAccount]::new($env:COMPUTERNAME,$UserId)}
    return $account.Translate([Security.Principal.SecurityIdentifier]).Value
}
function Get-OwnerTaskFileSddl([string]$TaskName) {
    if($TaskName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$' -or $TaskName.Contains('..')){throw 'Invalid task basename'}
    return (Get-Acl -LiteralPath (Join-Path $env:SystemRoot "System32/Tasks/$TaskName") -ErrorAction Stop).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
}
function Get-OwnerSHA256([byte[]]$Bytes) {
    $h = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() } finally { $h.Dispose() }
}
function Assert-StrictOwnerJson([byte[]]$Bytes) {
    if ($Bytes.Length -gt 1048576) { throw 'JSON exceeds command bound' }
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $s = $utf8.GetString($Bytes)
    $cursor = @{ Text=$s; Pos=0 }
    function Skip-OwnerWhitespace { while ($cursor.Pos -lt $cursor.Text.Length -and " `t`r`n".Contains([string]$cursor.Text[$cursor.Pos])) { $cursor.Pos++ } }
    function Read-OwnerString {
        $m = [regex]::Match($cursor.Text.Substring($cursor.Pos), '^"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"')
        if (!$m.Success) { throw 'Invalid JSON string' }
        $cursor.Pos += $m.Length
        return (ConvertFrom-Json -InputObject $m.Value)
    }
    function Read-OwnerValue([int]$Depth) {
        if ($Depth -gt 16) { throw 'JSON depth exceeded' }
        Skip-OwnerWhitespace
        if ($cursor.Pos -ge $cursor.Text.Length) { throw 'Missing JSON value' }
        $c = $cursor.Text[$cursor.Pos]
        if ($c -eq '"') { $null = Read-OwnerString; return }
        if ($c -eq '{' -or $c -eq '[') {
            $object = $c -eq '{'; $end = if ($object) { '}' } else { ']' }
            $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
            $cursor.Pos++; Skip-OwnerWhitespace
            if ($cursor.Pos -lt $cursor.Text.Length -and $cursor.Text[$cursor.Pos] -eq $end) { $cursor.Pos++; return }
            while ($true) {
                Skip-OwnerWhitespace
                if ($object) {
                    $key = Read-OwnerString
                    if (!$keys.Add($key)) { throw 'Duplicate JSON key' }
                    Skip-OwnerWhitespace
                    if ($cursor.Pos -ge $cursor.Text.Length -or $cursor.Text[$cursor.Pos] -ne ':') { throw 'Missing colon' }
                    $cursor.Pos++
                }
                Read-OwnerValue ($Depth+1); Skip-OwnerWhitespace
                if ($cursor.Pos -ge $cursor.Text.Length) { throw 'Unterminated container' }
                $separator = $cursor.Text[$cursor.Pos]; $cursor.Pos++
                if ($separator -eq $end) { return }
                if ($separator -ne ',') { throw 'Invalid separator' }
            }
        }
        $m = [regex]::Match($cursor.Text.Substring($cursor.Pos), '^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)')
        if (!$m.Success) { throw 'Invalid JSON token' }
        if ($m.Value -match '^[0-9-]') {
            $number = [double]::Parse($m.Value, [Globalization.CultureInfo]::InvariantCulture)
            if ([double]::IsInfinity($number) -or [double]::IsNaN($number)) { throw 'Nonfinite JSON number' }
        }
        $cursor.Pos += $m.Length
    }
    Read-OwnerValue 0; Skip-OwnerWhitespace
    if ($cursor.Pos -ne $s.Length) { throw 'Trailing JSON data' }
    return (ConvertFrom-Json -InputObject $s)
}
function Assert-OwnerFields($Value, [string[]]$Fields) {
    if ($null -eq $Value -or $Value -isnot [pscustomobject]) { throw 'Expected JSON object' }
    $actual = @($Value.PSObject.Properties | ForEach-Object { $_.Name })
    if ($actual.Count -ne $Fields.Count) { throw 'Unexpected field count' }
    foreach ($name in $actual) { if ($Fields -cnotcontains $name) { throw "Unknown field: $name" } }
}
function Get-OwnerReferenceNamespace($Name, [string[]]$AllowedNames = @('admission.json','producer-pins.json','admission-evidence.json','start-observation.json','policy-evidence.json','barrier-evidence.json','cleanup-request.json','drain.json','owner-exit.json','no-launch.json','supervisor-once.json','supervisor-exit-ready.json','original-producer-pin.json','readiness.json','reader-admissions.json','controls.jsonl','controls.pcap','controls-assessment.json','bfe.xml','rules.json','guids.json','gate.json','policy-assessment.json','barrier.json','barrier-journal.jsonl','admissions.json','reader-closures.json','task-closure.json','inspector-exit-proof.json','inspector-final.json','terminal.jsonl','stop-request.json','expected.json','launch.json','task-readback.json','registration.json' )) {
    if ($Name -isnot [string] -or $Name -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]*\.(?:jsonl?|xml|pcap)$' -or $Name.Contains('..')) { throw 'Invalid proof basename' }
    if ($Name -cmatch '^[1-9][0-9]*-(?:gate-status\.json|events\.jsonl|gate-request\.json|rules-bootstrap\.json|guids\.json|bfe-bootstrap\.xml|owner-once\.json)$') { return 'samples' }
    if ($AllowedNames -cnotcontains $Name -and $Name -cnotmatch '^reader-(?:supervisor|collector|barrier)-(?:ready|closed|session-open|started|signalled)\.json$') { throw 'Proof basename not allowlisted' }
    return 'proofs'
}
function Assert-OwnerRefs($Ref, [string]$Root, [string[]]$AllowedNames = $null, [long]$MaxBytes = 67108864) {
    Assert-OwnerFields $Ref @('name','sha256','length')
    $namespace = if ($null -eq $AllowedNames) { Get-OwnerReferenceNamespace $Ref.name } else { Get-OwnerReferenceNamespace $Ref.name $AllowedNames }
    if ($Ref.sha256 -isnot [string] -or $Ref.sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid proof hash' }
    if (($Ref.length -isnot [int] -and $Ref.length -isnot [long]) -or $Ref.length -lt 0 -or $Ref.length -gt $MaxBytes) { throw 'Invalid proof length' }
    if ($Root) {
        $bytes = Read-OwnerBytes (Join-Path $Root ('transport/' + $namespace + '/' + $Ref.name)) $MaxBytes $Root
        if ($bytes.LongLength -ne $Ref.length -or (Get-OwnerSHA256 $bytes) -cne $Ref.sha256) { throw 'Proof bytes mismatch' }
    }
}
function Assert-OwnerEnvelope([byte[]]$Bytes, [string]$Nonce, [string]$ConfigSHA256, [long]$Sequence) {
    $v = Assert-StrictOwnerJson $Bytes
    Assert-OwnerFields $v @('schema','nonce','configSHA256','seq','op','body')
    if ($v.schema -cne 'full300-owner-command-v1' -or $v.nonce -isnot [string] -or $v.nonce -cnotmatch '^[0-9a-f]{64}$' -or $v.nonce -cne $Nonce -or $v.configSHA256 -isnot [string] -or $v.configSHA256 -cnotmatch '^[0-9a-f]{64}$' -or $v.configSHA256 -cne $ConfigSHA256) { throw 'Envelope binding mismatch' }
    if (($v.seq -isnot [int] -and $v.seq -isnot [long]) -or $v.seq -le 0 -or $v.seq -ne $Sequence) { throw 'Invalid sequence' }
    $fields = switch -CaseSensitive ($v.op) {
        'launch' { @('admission','producerPins','admissionEvidence') }
        'sample' { @() }
        'start' { @('request','policyEvidence','barrierEvidence') }
        'cleanup' { @('request','drain') }
        'seal-no-launch' { @() }
        'exit-supervisor' { if (@($v.body.PSObject.Properties | ForEach-Object { $_.Name }) -ccontains 'ownerExit') { 'ownerExit' } else { 'noLaunch' } }
        default { throw 'Unknown operation' }
    }
    Assert-OwnerFields $v.body @($fields | Where-Object { $null -ne $_ })
    foreach ($field in $fields) { Assert-OwnerRefs $v.body.$field }
    return $v
}



# The caller supplies the trusted run root; tests supply an exclusive local root.
function Assert-OwnerFilePath([string]$Path, [string]$Root) {
    if (!$Root -or ![IO.Path]::IsPathRooted($Root) -or ![IO.Path]::IsPathRooted($Path)) { throw 'Absolute root and path required' }
    $base = [IO.Path]::GetFullPath($Root).TrimEnd('\','/')
    $full = [IO.Path]::GetFullPath($Path)
    if (!$full.StartsWith($base + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Path outside owner root' }
    if ($Path -match '(^|[\\/])\.\.?([\\/]|$)' -or $full.Substring(2).Contains(':') -or $full.StartsWith('\\')) { throw 'Unsafe owner path' }
    $parent = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($full))
    while ($null -ne $parent) {
        if (!$parent.Exists -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Missing or reparse parent' }
        $parent = $parent.Parent
    }
    if (Test-Path -LiteralPath $full) {
        $item = Get-Item -LiteralPath $full -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.LinkType) { throw 'Unsafe linked owner file' }
    }
    return $full
}
function Read-OwnerBytes([string]$Path, [long]$MaxBytes = 1048576, [string]$Root) {
    if ($MaxBytes -lt 0 -or $MaxBytes -gt 67108864) { throw 'Invalid byte bound' }
    $full = Assert-OwnerFilePath $Path $Root
    $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $null = Assert-OwnerFilePath $full $Root
        $length = $stream.Length
        if ($length -gt $MaxBytes) { throw 'Owner file exceeds bound' }
        $bytes = [byte[]]::new([int]$length)
        $offset = 0
        $clock = [Diagnostics.Stopwatch]::StartNew()
        while ($offset -lt $length) {
            $count = $stream.Read($bytes, $offset, [Math]::Min(65536, $length-$offset))
            if (!$count -or $clock.ElapsedMilliseconds -gt 5000) { throw 'Short or overdue owner read' }
            $offset += $count
        }
        if ($stream.ReadByte() -ne -1 -or $stream.Length -ne $length) { throw 'Owner file changed' }
        return ,$bytes
    } finally { $stream.Dispose() }
}
function Publish-OwnerBytesOnce([string]$Path, [byte[]]$Bytes, [string]$Root, [long]$MaxBytes = 1048576) {
    if ($null -eq $Bytes -or $MaxBytes -lt 0 -or $MaxBytes -gt 67108864 -or $Bytes.LongLength -gt $MaxBytes) { throw 'Invalid publication size' }
    $full = Assert-OwnerFilePath $Path $Root
    $temp = $null
    try {
        if (![IO.File]::Exists($full)) {
            $temp = Join-Path ([IO.Path]::GetDirectoryName($full)) ('.owner-' + [Guid]::NewGuid().ToString('N') + '.tmp')
            $null = Assert-OwnerFilePath $temp $Root
            $stream = [IO.File]::Open($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $stream.Write($Bytes,0,$Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
            $null = Assert-OwnerFilePath $full $Root
            try { [IO.File]::Move($temp,$full); $temp = $null } catch [IO.IOException] { if (![IO.File]::Exists($full)) { throw } }
        }
        $existing = Read-OwnerBytes $full $MaxBytes $Root
        if ($existing.Length -ne $Bytes.Length) { throw 'Immutable publication conflict' }
        for ($i=0; $i -lt $Bytes.Length; $i++) { if ($existing[$i] -ne $Bytes[$i]) { throw 'Immutable publication conflict' } }
    } finally { if ($temp -and [IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
}

# Enumerate exact hash-bound dependency closure before any command publication.
# Directory is the transport directory containing both proofs and samples.
function Get-OwnerProofContainerSchema([string]$Name) {
 # Only these transport wrappers contain references. Raw policy/native and
 # provenance evidence are hash-bound leaves, validated by their own consumers.
 # In particular rules.json is NOT a command JSON document (64 MiB byte cap).
 switch -CaseSensitive ($Name) {
  'admission-evidence.json' { return 'full300-launch-evidence-v1' }
  'policy-evidence.json' { return 'full300-policy-evidence-v1' }
  'barrier-evidence.json' { return 'full300-barrier-evidence-v1' }
  'drain.json' { return 'full300-drain-v1' }
  'task-closure.json' { return 'full300-task-closure-v1' }
  'task-readback.json' { return 'full300-task-readback-v1' }
  'admissions.json' { return 'full300-reader-admissions-v1' }
  'reader-closures.json' { return 'full300-reader-closures-v1' }
  'owner-exit.json' { return 'full300-owner-exit-v1' }
 }
 if($Name -cmatch '^reader-(?:supervisor|collector|barrier)-signalled\.json$'){return 'full300-local-transport-v1'}
 return $null
}
function Get-OwnerTransitiveProofs($Value,[string]$Directory,[string]$Root,$Seen=@{}) {
 if($null -eq $Value){return}
 if($Value -is [pscustomobject]){
  # Strict-mode safe: member enumeration of an empty object (e.g. {} bodies)
  # throws PropertyNotFound under Set-StrictMode -Version Latest.
  $names=@($Value.PSObject.Properties|ForEach-Object {$_.Name})
  if($names -contains 'sha256' -and $names -contains 'name' -and $names -contains 'length'){
   Assert-OwnerRefs $Value
   $namespace=Get-OwnerReferenceNamespace $Value.name
   $bytes=Read-OwnerBytes (Join-Path $Directory ($namespace + '/' + $Value.name)) -Root $Root -MaxBytes 67108864
   if($bytes.Length -ne $Value.length -or (Get-OwnerSHA256 $bytes) -cne $Value.sha256){throw 'Transitive proof mismatch'}
   if($Seen.ContainsKey($Value.name)){if($Seen[$Value.name] -cne $Value.sha256){throw 'Conflicting transitive reference'};return}
   $Seen[$Value.name]=$Value.sha256
   $schema=Get-OwnerProofContainerSchema $Value.name
   if($schema){
    $container=Assert-StrictOwnerJson $bytes
    if($container -isnot [pscustomobject] -or $container.schema -cne $schema){throw 'Transitive wrapper schema mismatch'}
    Get-OwnerTransitiveProofs $container $Directory $Root $Seen
   }
   @{name=$Value.name;bytes=$bytes};return
  }
  foreach($p in $Value.PSObject.Properties){Get-OwnerTransitiveProofs $p.Value $Directory $Root $Seen}
 }elseif($Value -is [array]){foreach($v in $Value){Get-OwnerTransitiveProofs $v $Directory $Root $Seen}}
}
