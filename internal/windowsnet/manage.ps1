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
    if (@(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $taskConfig.name }).Count -gt 0) { throw 'Tunnel name is already in use.' }
    if (@($rules | Where-Object { -not ($_.Comment -and $_.Comment.StartsWith($ownerPrefix)) }).Count -gt 0) { throw 'Existing NRPT rules detected. Run bimeron recover for stale Bimeron rules; other NRPT policies are not supported yet.' }
    # While the Group Policy NRPT key exists, even empty, Windows ignores every
    # local rule, so the session's '.' rule would have no effect and names
    # would resolve outside the tunnel.
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig') { throw 'Existing NRPT rules detected from Group Policy; they override the session DNS rule and are not supported.' }
    $true | ConvertTo-Json -Compress
 }
 'setup' {
    if (-not $taskConfig.tag.StartsWith($ownerPrefix)) { throw 'Invalid session owner.' }
    # Select the created adapter by its verified index, never by name, and
    # check its name before changing anything.
    $adapter = @(Get-NetAdapter -InterfaceIndex $taskConfig.index -ErrorAction Stop)
    if ($adapter.Count -ne 1 -or $adapter[0].Name -cne $taskConfig.name -or [int]$adapter[0].ifIndex -ne [int]$taskConfig.index) { throw 'Tunnel adapter identity changed.' }
    $index = [int]$adapter[0].ifIndex
    try {
      $clock = [Diagnostics.Stopwatch]::StartNew()
      Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Dhcp Disabled -NlMtuBytes $taskConfig.mtu -AutomaticMetric Disabled -InterfaceMetric 1 | Out-Null
      Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -NlMtuBytes $taskConfig.mtu -AutomaticMetric Disabled -InterfaceMetric 1 | Out-Null
      $interfaceMs = $clock.ElapsedMilliseconds
      Set-DnsClient -InterfaceIndex $index -RegisterThisConnectionsAddress $false | Out-Null
      Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses '198.18.0.2' | Out-Null
      $dnsMs = $clock.ElapsedMilliseconds - $interfaceMs
      Add-DnsClientNrptRule -Namespace '.' -NameServers '198.18.0.2' -Comment $taskConfig.tag | Out-Null
      # The effective view can lag behind a successful local rule installation.
      for ($attempt = 0; $attempt -lt 21; $attempt++) {
        $effective = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
        if ($effective.Count -eq 1 -and @($effective[0].Namespace).Count -eq 1 -and
            $effective[0].Namespace -contains '.' -and @($effective[0].NameServers).Count -eq 1 -and
            $effective[0].NameServers -contains '198.18.0.2') { break }
        if ($attempt -eq 20) { throw 'The effective NRPT policy does not direct DNS to the tunnel.' }
        Start-Sleep -Milliseconds 250
      }
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
