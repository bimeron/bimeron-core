$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ownerPrefix = 'BimeronCore:'
function Remove-OwnedDns($tag) {
    $rules = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Comment -eq $tag })
    foreach ($rule in $rules) { Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop }
}
switch ($taskConfig.action) {
 'inspect' {
    # Recover stale Bimeron DNS policy before checking for conflicting policies.
    try {
      $rules = @(Get-DnsClientNrptRule)
      $owned = @($rules | Where-Object { $_.Comment -and $_.Comment.StartsWith($ownerPrefix) })
      foreach ($rule in $owned) { Remove-DnsClientNrptRule -Name $rule.Name -Force }
      Clear-DnsClientCache
    } catch { throw 'DNS recovery failed.' }
    if (Get-NetAdapter -Name $taskConfig.name -ErrorAction SilentlyContinue) { throw 'Tunnel name is already in use.' }
    if (@($rules | Where-Object { -not ($_.Comment -and $_.Comment.StartsWith($ownerPrefix)) }).Count -gt 0) { throw 'Existing NRPT rules detected. Run bimeron recover for stale Bimeron rules; other NRPT policies are not supported yet.' }
    $true | ConvertTo-Json -Compress
 }
 'setup' {
    if (-not $taskConfig.tag.StartsWith($ownerPrefix)) { throw 'Invalid session owner.' }
    $adapter = Get-NetAdapter -Name $taskConfig.name -ErrorAction Stop
    $index = [int]$adapter.ifIndex
    try {
      $clock = [Diagnostics.Stopwatch]::StartNew()
      Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Dhcp Disabled -NlMtuBytes $taskConfig.mtu -AutomaticMetric Disabled -InterfaceMetric 1 | Out-Null
      Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -NlMtuBytes $taskConfig.mtu -AutomaticMetric Disabled -InterfaceMetric 1 | Out-Null
      $interfaceMs = $clock.ElapsedMilliseconds
      Set-DnsClient -InterfaceIndex $index -RegisterThisConnectionsAddress $false | Out-Null
      Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses '198.18.0.2' | Out-Null
      $dnsMs = $clock.ElapsedMilliseconds - $interfaceMs
      Add-DnsClientNrptRule -Namespace '.' -NameServers '198.18.0.2' -Comment $taskConfig.tag | Out-Null
      $nrptMs = $clock.ElapsedMilliseconds - $interfaceMs - $dnsMs
      Clear-DnsClientCache
      @{index=$index;interfaceMs=$interfaceMs;dnsMs=$dnsMs;nrptMs=$nrptMs;cacheMs=($clock.ElapsedMilliseconds - $interfaceMs - $dnsMs - $nrptMs)} | ConvertTo-Json -Compress
    } catch {
      $failure = $_
      Remove-OwnedDns $taskConfig.tag
      throw $failure
    }
 }
 'cleanup' {
    if (-not $taskConfig.tag.StartsWith($ownerPrefix)) { throw 'Invalid session owner.' }
    $failures = @()
    # Remove DNS first so no process keeps querying the soon-to-close tunnel.
    try { Remove-OwnedDns $taskConfig.tag } catch { $failures += $_ }
    try { Clear-DnsClientCache } catch { $failures += $_ }
    if ($failures.Count -gt 0) { throw 'Could not restore all owned network settings. Run bimeron recover.' }
 }
 'recover' {
    # Only our explicitly tagged DNS rules; never touch other software's rules.
    $rules = @(Get-DnsClientNrptRule | Where-Object { $_.Comment -and $_.Comment.StartsWith($ownerPrefix) })
    foreach ($rule in $rules) { Remove-DnsClientNrptRule -Name $rule.Name -Force }
    Clear-DnsClientCache
 }
 default { throw 'Unknown network operation.' }
}
