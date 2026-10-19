$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ownerPrefix = 'BimeronCore:'
function Remove-OwnedDns($tag) {
    $rules = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Comment -eq $tag })
    foreach ($rule in $rules) { Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop }
}
function Get-OutboundPath {
    # Exclude VPN/virtual defaults, especially another VPN's IPv6 default.
    $physical = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.ifIndex })
    $v4 = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -in $physical -and $_.NextHop -ne '0.0.0.0' } | Sort-Object @{Expression={ $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric }},InterfaceIndex,NextHop)
    $v6 = @(Get-NetRoute -AddressFamily IPv6 -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -in $physical -and $_.DestinationPrefix -eq '::/0' } | Sort-Object @{Expression={ $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv6).InterfaceMetric }},InterfaceIndex,NextHop)
    if ($v4.Count -eq 0) { throw 'No physical IPv4 default gateway found.' }
    $i4=[int]$v4[0].InterfaceIndex; $i6=0; $g6=''
    if ($v6.Count -gt 0) { $i6=[int]$v6[0].InterfaceIndex; $g6=[string]$v6[0].NextHop }
    $addresses = @(Get-NetIPAddress | Where-Object { $_.InterfaceIndex -in @($i4,$i6) -and $_.AddressState -eq 'Preferred' } | ForEach-Object { "$($_.InterfaceIndex):$($_.IPAddress)/$($_.PrefixLength)" } | Sort-Object)
    $dns = @((Get-DnsClientServerAddress -InterfaceIndex $i4 -AddressFamily IPv4).ServerAddresses | Sort-Object -Unique)
    @{ipv4=$i4;ipv6=$i6;gateway4=[string]$v4[0].NextHop;gateway6=$g6;addresses=($addresses -join ',');dns=$dns} | ConvertTo-Json -Compress
}
switch ($taskConfig.action) {
 'inspect' {
    if (Get-NetAdapter -Name $taskConfig.name -ErrorAction SilentlyContinue) { throw 'Tunnel name is already in use.' }
    if (@(Get-DnsClientNrptRule).Count -gt 0) { throw 'Existing NRPT rules detected. Run bimeron recover for stale Bimeron rules; other NRPT policies are not supported yet.' }
    Get-OutboundPath
 }
 'observe' {
    if (-not (Get-NetAdapter -Name $taskConfig.name -ErrorAction SilentlyContinue)) { throw 'Tunnel adapter disappeared.' }
    Get-OutboundPath
 }
 'setup' {
    if (-not $taskConfig.tag.StartsWith($ownerPrefix)) { throw 'Invalid session owner.' }
    $adapter = Get-NetAdapter -Name $taskConfig.name -ErrorAction Stop
    $index = [int]$adapter.ifIndex
    try {
      Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Dhcp Disabled -NlMtuBytes $taskConfig.mtu -AutomaticMetric Disabled -InterfaceMetric 1 | Out-Null
      Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -NlMtuBytes $taskConfig.mtu -AutomaticMetric Disabled -InterfaceMetric 1 | Out-Null
      New-NetIPAddress -InterfaceIndex $index -IPAddress '198.18.0.1' -PrefixLength 30 -AddressFamily IPv4 -PolicyStore ActiveStore | Out-Null
      New-NetIPAddress -InterfaceIndex $index -IPAddress 'fd69:726f:7574::1' -PrefixLength 128 -AddressFamily IPv6 -PolicyStore ActiveStore | Out-Null
      Set-DnsClient -InterfaceIndex $index -RegisterThisConnectionsAddress $false | Out-Null
      Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses '198.18.0.2' | Out-Null
      # More-specific routes leave original default routes intact.
      foreach ($prefix in @('0.0.0.0/1','128.0.0.0/1')) {
        New-NetRoute -InterfaceIndex $index -DestinationPrefix $prefix -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
      }
      foreach ($prefix in @('::/1','8000::/1')) {
        New-NetRoute -InterfaceIndex $index -DestinationPrefix $prefix -NextHop '::' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
      }
      Add-DnsClientNrptRule -Namespace '.' -NameServers '198.18.0.2' -Comment $taskConfig.tag | Out-Null
      Clear-DnsClientCache
      $index | ConvertTo-Json -Compress
    } catch {
      $failure = $_
      Remove-OwnedDns $taskConfig.tag
      Get-NetRoute -InterfaceIndex $index -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') } | Remove-NetRoute -Confirm:$false
      throw $failure
    }
 }
 'cleanup' {
    if (-not $taskConfig.tag.StartsWith($ownerPrefix)) { throw 'Invalid session owner.' }
    $failures = @()
    # Remove DNS first so no process keeps querying the soon-to-close tunnel.
    try { Remove-OwnedDns $taskConfig.tag } catch { $failures += $_ }
    try { if ($taskConfig.index -gt 0) {
      $adapter = Get-NetAdapter -InterfaceIndex $taskConfig.index -ErrorAction SilentlyContinue
      if ($adapter -and $adapter.Name -eq $taskConfig.name) {
        Get-NetRoute -InterfaceIndex $taskConfig.index -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') } | Remove-NetRoute -Confirm:$false
      }
    } } catch { $failures += $_ }
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
