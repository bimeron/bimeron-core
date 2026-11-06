param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][string]$Nonce,[Parameter(Mandatory=$true)][string]$ConfigSHA256)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/owner-mailbox.ps1"
. "$PSScriptRoot/resident-guest.ps1"
function Write-ResidentBytes([string]$Name,[byte[]]$Bytes){Publish-ResidentBytesOnce $Root $Name $Bytes}
function Publish-Resident([string]$Name,$Value){Write-ResidentBytes $Name ([Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 20 -Compress)))}
$state=New-ResidentGuestState $Nonce $ConfigSHA256
# The native bootstrap retains no-delete/no-write-sharing root/source pins.
# Recheck this existing private directory independently before endpoint use.
$item=Get-Item -LiteralPath $Root -Force
if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Resident root type'}
$acl=Get-Acl -LiteralPath $Root;$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if(!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid){throw 'Resident root owner/protection'}
$aces=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));$seen=@{}
if($aces.Count -ne 3){throw 'Resident root ACE count'}
foreach($ace in $aces){$id=$ace.IdentityReference.Value;if($id -cnotin @($sid,'S-1-5-18','S-1-5-32-544') -or $seen.ContainsKey($id) -or $ace.IsInherited -or $ace.AccessControlType -ne 'Allow' -or [int]$ace.FileSystemRights -ne 2032127 -or [int]$ace.InheritanceFlags -ne 3 -or [int]$ace.PropagationFlags -ne 0){throw 'Resident root ACE'};$seen[$id]=$true}
Publish-Resident 'resident-ready.json' @{schema='fresh-resident-ready-v1';nonce=$Nonce;configSHA256=$ConfigSHA256}
while(!$state.finished){
 try {
  if($null -ne $state.active -and $state.active.state -ceq 'Reserved'){
   $null=Submit-ResidentRequest $state $state.active.request {param($id,$raw)Write-ResidentBytes ('resident-reserved-{0:D20}.json' -f $id) ([Text.UTF8Encoding]::new($false).GetBytes($raw))}
  }
  if($null -ne $state.active -and $state.active.state -ceq 'Pending'){$null=Collect-ResidentOriginal $state}
  if($null -ne $state.active -and $state.active.state -cin @('Collected','Failed')){
   $record=$state.active
   Publish-Resident ('resident-response-{0:D20}.json' -f $record.request.sequence) (Get-ResidentResponse $state $record)
  }
  $raw=Read-ResidentPublished (Join-Path $Root ('resident-request-{0:D20}.json' -f ($state.sequence+1)))
  if($null -ne $raw){
   $value=Assert-StrictOwnerJson $raw;$request=@{}
   foreach($property in $value.PSObject.Properties){$request[$property.Name]=$property.Value}
   $null=Submit-ResidentRequest $state $request {param($id,$raw)Write-ResidentBytes ('resident-reserved-{0:D20}.json' -f $id) ([Text.UTF8Encoding]::new($false).GetBytes($raw))}
  }
  $raw=Read-ResidentPublished (Join-Path $Root 'resident-close-request.json')
  if($null -ne $raw){
   $value=Assert-StrictOwnerJson $raw
   Assert-OwnerFields $value @('schema','nonce','configSHA256','lastSequence')
   if($value.schema -cne 'fresh-resident-close-v1' -or $value.nonce -cne $Nonce -or $value.configSHA256 -cne $ConfigSHA256 -or $value.lastSequence -ne $state.sequence){throw 'Resident closure binding'}
   $closed=Close-ResidentOriginal $state {param($id,$raw)Publish-Resident 'resident-close-reserved.json' $value}
   Publish-Resident 'resident-closed.json' $closed
  }
  $raw=Read-ResidentPublished (Join-Path $Root 'resident-finish-request.json')
  if($null -ne $raw){
   $value=Assert-StrictOwnerJson $raw
   Assert-OwnerFields $value @('schema','nonce','configSHA256','closureSHA256')
   if(!$state.closed -or $value.schema -cne 'fresh-resident-finish-v1' -or $value.nonce -cne $Nonce -or $value.configSHA256 -cne $ConfigSHA256 -or $value.closureSHA256 -cne (Get-OwnerSHA256 ([IO.File]::ReadAllBytes((Join-Path $Root 'resident-closed.json'))))){throw 'Resident finish binding'}
   Publish-Resident 'resident-finished.json' $value
   $state.finished=$true
  }
 }catch{
  if($null -eq $state.failure){$state.failure=[string]$_.Exception.Message}
  # Original shared state/runspace/Session/PowerShell objects remain in this loop.
  # No timeout, exception, or publication failure disposes or replaces them.
 }
 if(!$state.finished){Start-Sleep -Milliseconds 50}
}
exit 0
