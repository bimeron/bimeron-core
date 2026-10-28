$ErrorActionPreference = 'Stop'
switch ($taskConfig.action) {
 'inspect' {
    if (@(Get-DnsClientNrptRule -ErrorAction Stop).Count -ne 0 -or @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop).Count -ne 0) { throw 'Conflicting DNS policy; recover owned policy or consult the administrator.' }
 }
 'setup' {
    if ($taskConfig.tag -notmatch '^BimeronIKEv2DNS:[a-f0-9]{32}$') { throw 'Invalid native DNS owner.' }
    if (@(Get-DnsClientNrptRule -ErrorAction Stop).Count -ne 0 -or @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop).Count -ne 0) { throw 'Conflicting DNS policy.' }
    Add-DnsClientNrptRule -Namespace '.' -NameServers $taskConfig.dns -Comment $taskConfig.tag -ErrorAction Stop | Out-Null
    Clear-DnsClientCache
 }
 'cleanup' {
    if ($taskConfig.tag -notmatch '^BimeronIKEv2DNS:[a-f0-9]{32}$') { throw 'Invalid native DNS owner.' }
    $rules = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object Comment -eq $taskConfig.tag)
    foreach ($rule in $rules) {
      if (@($rule.Namespace).Count -ne 1 -or $rule.Namespace[0] -ne '.' -or (Compare-Object @($rule.NameServers | Sort-Object) @($taskConfig.dns | Sort-Object))) { throw 'Owned DNS policy changed; explicit recovery required.' }
      Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop
    }
    Clear-DnsClientCache
 }
 'recover' {
    $rules = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Comment -match '^BimeronIKEv2DNS:[a-f0-9]{32}$' })
    foreach ($rule in $rules) { Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop }
    Clear-DnsClientCache
 }
 default { throw 'Unknown native DNS operation.' }
}
