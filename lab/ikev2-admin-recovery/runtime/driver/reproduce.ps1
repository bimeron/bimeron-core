param([string]$Manifest="$PSScriptRoot/freeze-v1/manifest.json")
$ErrorActionPreference='Stop'
$go=Join-Path $env:USERPROFILE 'go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.windows-amd64/bin/go.exe'
if(!(Test-Path $go)){throw 'Installed Go1.26.9 required; no download'}
$entries=Get-Content -Raw $Manifest|ConvertFrom-Json;$freeze=Split-Path $Manifest
foreach($e in $entries){
 if((Get-FileHash -LiteralPath $e.Path).Hash -ne $e.SHA256){throw "Current bytes mismatch: $($e.Path)"}
 if((Get-FileHash -LiteralPath (Join-Path $freeze $e.Snapshot)).Hash -ne $e.SHA256){throw "Frozen bytes mismatch: $($e.Path)"}
}
$out=Join-Path ([IO.Path]::GetTempPath()) ('step10-reproduce-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $out -ErrorAction Stop|Out-Null
$old=$env:GOTOOLCHAIN
try{
 $env:GOTOOLCHAIN='local'
 if((& $go env GOVERSION) -ne 'go1.26.9'){throw 'Wrong toolchain'}
 & $go build -trimpath -o "$out/step10-candidate.exe" ./build/step10-probe/source
 if($LASTEXITCODE){throw 'Build failed'}
 $expected=@($entries|Where-Object {$_.Path -eq (Join-Path $PSScriptRoot 'step10-candidate.exe')})
 if($expected.Count -ne 1){throw 'Candidate binding missing'}
 $hash=(Get-FileHash "$out/step10-candidate.exe").Hash
 if($hash -ne $expected[0].SHA256){throw 'Reproduction mismatch'}
 "MATCH $hash; output $out"
}finally{$env:GOTOOLCHAIN=$old}
