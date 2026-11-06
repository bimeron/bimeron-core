function Assert-Fields($Value,[string[]]$Names) {
 if($null -eq $Value -or $Value -isnot [pscustomobject]){throw 'Expected object'}
 $actual=@($Value.PSObject.Properties.Name|Sort-Object);$wanted=@($Names|Sort-Object)
 if(($actual -join '|') -cne ($wanted -join '|')){throw 'Unexpected schema fields'}
}
function Assert-Text($Value){if($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)){throw 'Expected nonempty string'}}
function Get-ProbeInputNames {return @('wrapper','Journal.cs','ProcessPin.cs','probe.ps1','inspect-producer.ps1','provenance.ps1','export-expected.ps1','expected-schema.ps1','snapshot.ps1','file-sha256.ps1','cancellation.ps1')}
function Assert-ExpectedSchema($Expected,[string]$Nonce,[string]$BaseRoot) {
 $BaseRoot=$BaseRoot.Replace('\','/')
 Assert-Fields $Expected @('schemaVersion','nonce','registration','images','inputs','baseline')
 if(($Expected.schemaVersion -isnot [int] -and $Expected.schemaVersion -isnot [long]) -or $Expected.schemaVersion -ne 1 -or $Expected.nonce -isnot [string] -or $Expected.nonce -cne $Nonce -or $Nonce -cnotmatch '^[a-f0-9]{64}$'){throw 'Schema version/nonce'}
 Assert-Text $Expected.baseline
 if($Expected.baseline -cne 'New independently inspected full XML, not historical full XML parity'){throw 'Baseline label'}
 $names=@(Get-ProbeInputNames)
 if($Expected.inputs -isnot [array] -or $Expected.inputs.Count -ne $names.Count){throw 'Inputs must be exact array'}
 for($i=0;$i -lt $names.Count;$i++){
  $item=$Expected.inputs[$i];Assert-Fields $item @('role','path','sha256')
  foreach($key in @('role','path','sha256')){Assert-Text $item.$key}
  $path=if($i -eq 0){'C:/BimeronStep8/probe.ps1'}else{"$BaseRoot/$($names[$i])"}
  if($item.role -cne $names[$i] -or $item.path -cne $path -or $item.sha256 -cnotmatch '^[A-Fa-f0-9]{64}$'){throw 'Input role/path/hash'}
 }
 $r=$Expected.registration;Assert-Fields $r @('xml','path','security','action','principal')
 foreach($k in @('xml','path','security')){Assert-Text $r.$k}
 if($r.path -cne '\BimeronStep8Probe'){throw 'Task path'}
 $xml=[xml]$r.xml;if($xml.DocumentElement.LocalName -cne 'Task' -or $xml.DocumentElement.NamespaceURI -cne 'http://schemas.microsoft.com/windows/2004/02/mit/task'){throw 'Task XML'}
 $null=[Security.AccessControl.RawSecurityDescriptor]::new($r.security)
 if($r.action -isnot [array] -or $r.action.Count -ne 1){throw 'Action array'}
 $a=$r.action[0];Assert-Fields $a @('Execute','Arguments','WorkingDirectory')
 Assert-Text $a.Execute;Assert-Text $a.Arguments
 if($a.Execute -cne 'cmd.exe' -or $a.Arguments -cne '/c powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\BimeronStep8\probe.ps1 -Seconds 8 > C:\BimeronStep8Probe\task.txt 2>&1' -or $null -ne $a.WorkingDirectory){throw 'Action expectation'}
 $p=$r.principal;Assert-Fields $p @('sid','logon','level','token','privileges')
 Assert-Text $p.sid
 if($p.sid -cne '<LAB_GUEST_SID_1002>' -or ($p.logon -isnot [int] -and $p.logon -isnot [long]) -or $p.logon -ne 1 -or ($p.level -isnot [int] -and $p.level -isnot [long]) -or $p.level -ne 0 -or ($p.token -isnot [int] -and $p.token -isnot [long]) -or $p.token -ne 2 -or $p.privileges -isnot [array] -or $p.privileges.Count -ne 0){throw 'Principal expectation'}
 Assert-Fields $Expected.images @('cmd','powershell')
 $fixed=@{cmd=@('C:\Windows\System32\cmd.exe','B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450');powershell=@('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','9F914D42706FE215501044ACD85A32D58AAEF1419D404FDDFA5D3B48F66CCD9F')}
 foreach($name in @('cmd','powershell')){
  $im=$Expected.images.$name;Assert-Fields $im @('path','sha256','arguments')
  Assert-Text $im.path;Assert-Text $im.sha256
  if($im.path -cne $fixed[$name][0] -or $im.sha256 -ine $fixed[$name][1] -or $im.arguments -isnot [array] -or !$im.arguments.Count){throw 'Image expectation'}
  foreach($arg in $im.arguments){Assert-Text $arg}
  $argsExpected=if($name -eq 'cmd'){@([ProcessPin]::Arguments('cmd.exe '+$a.Arguments))}else{@('-NoProfile','-ExecutionPolicy','Bypass','-File','C:\BimeronStep8\probe.ps1','-Seconds','8')}
  if(($im.arguments|ConvertTo-Json -Compress) -cne ($argsExpected|ConvertTo-Json -Compress)){throw 'Image arguments'}
 }
}
