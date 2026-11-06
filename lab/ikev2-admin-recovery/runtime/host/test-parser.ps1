$ErrorActionPreference='Stop'
foreach($name in @('publish-live.ps1','test-parser.ps1')) {
 $tokens=$null;$parseErrors=$null
 $null=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$parseErrors)
 if($parseErrors.Count){throw ($parseErrors.Message -join '; ')}
}
Write-Output 'PowerShell syntax passed; no operational scripts executed.'
