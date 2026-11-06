param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][string]$Destination)
$ErrorActionPreference='Stop'
$Source=(Resolve-Path $Source).Path
if(Test-Path $Destination){throw 'Archive collision'}
New-Item -ItemType Directory $Destination -ErrorAction Stop|Out-Null
$Destination=(Resolve-Path $Destination).Path
$longest=0
foreach($file in Get-ChildItem -LiteralPath $Source -File -Recurse){
 $relative=$file.FullName.Substring($Source.Length).TrimStart('\')
 $target=Join-Path (Join-Path $Destination 'guest') $relative
 $longest=[Math]::Max($longest,$target.Length)
 if($target.Length -ge 260){throw 'Archive path bound'}
}
Copy-Item -LiteralPath $Source -Destination (Join-Path $Destination 'guest') -Recurse
foreach($file in Get-ChildItem -LiteralPath $Source -File -Recurse){
 $relative=$file.FullName.Substring($Source.Length).TrimStart('\')
 if((Get-FileHash -LiteralPath $file.FullName).Hash -ne (Get-FileHash -LiteralPath (Join-Path (Join-Path $Destination 'guest') $relative)).Hash){throw 'Archive hash mismatch'}
}
$collision=$false;try{New-Item -ItemType Directory $Destination -ErrorAction Stop|Out-Null}catch{$collision=$true}
if(!$collision){throw 'Collision not refused'}
@{longestDestination=$longest;collisionRefused=$collision;allHashesMatch=$true}|ConvertTo-Json|Set-Content (Join-Path $Destination 'result.json')
