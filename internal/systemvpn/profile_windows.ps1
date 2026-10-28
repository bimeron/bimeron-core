$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$config = [Console]::In.ReadToEnd() | ConvertFrom-Json
function Find-Profile {
    $profiles = @(Get-VpnConnection -ErrorAction Stop | Where-Object Name -eq $config.name)
    $machine = @(Get-VpnConnection -AllUserConnection -ErrorAction Stop | Where-Object Name -eq $config.name)
    if ($machine.Count -ne 0 -or $profiles.Count -gt 1) { throw 'Profile name collision.' }
    if ($profiles.Count -eq 0) { return $null }
    if ($profiles[0].ConnectionStatus -ne 'Disconnected') { throw 'Profile is active.' }
    return $profiles[0]
}
function Public-Settings($profile) {
    if ($null -eq $profile) { return '' }
    # Deliberately exclude credential/EAP user data. EapConfigXmlStream is the public method policy.
    $policy = @($profile.IPsecCustomPolicy | Select-Object AuthenticationTransformConstants,CipherTransformConstants,DHGroup,EncryptionMethod,IntegrityCheckMethod,PfsGroup,SALifeTimeSeconds,MMSALifeTimeSeconds,SADataSizeKilobytes)
    $routes = @($profile.Routes | Sort-Object DestinationPrefix | Select-Object DestinationPrefix,RouteMetric)
    return ([ordered]@{
        Name = $profile.Name; Guid = [string]$profile.Guid; ServerAddress = $profile.ServerAddress
        TunnelType = [string]$profile.TunnelType; AuthenticationMethod = @($profile.AuthenticationMethod | ForEach-Object { [string]$_ })
        EncryptionLevel = [string]$profile.EncryptionLevel; SplitTunneling = $profile.SplitTunneling
        RememberCredential = $profile.RememberCredential; DnsSuffix = $profile.DnsSuffix
        IdleDisconnectSeconds = $profile.IdleDisconnectSeconds
        EapPolicy = $profile.EapConfigXmlStream.OuterXml; IPsec = $policy; Routes = $routes
    } | ConvertTo-Json -Depth 8 -Compress)
}
$createdGuid = $null
try {
    $profile = Find-Profile
    switch ($config.action) {
        'inspect' { [Console]::Write((Public-Settings $profile)); exit 0 }
        'create' {
            if ($null -ne $profile) { throw 'Profile already exists.' }
            $eap = New-EapConfiguration -ErrorAction Stop
            Add-VpnConnection -Name $config.name -ServerAddress $config.server -TunnelType Ikev2 -AuthenticationMethod Eap -EapConfigXmlStream $eap.EapConfigXmlStream -EncryptionLevel Required -RememberCredential -SplitTunneling:$false -ErrorAction Stop | Out-Null
            $profile = Find-Profile
            $createdGuid = [string]$profile.Guid
            Set-VpnConnectionIPsecConfiguration -ConnectionName $config.name -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES256 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 -PfsGroup None -Force -ErrorAction Stop | Out-Null
            foreach ($prefix in @('::/1', '8000::/1')) {
                Add-VpnConnectionRoute -ConnectionName $config.name -DestinationPrefix $prefix -RouteMetric 1 -ErrorAction Stop | Out-Null
            }
            [Console]::Write($createdGuid)
        }
        'remove' {
            if ($null -eq $profile -or (Public-Settings $profile) -cne $config.expected) { throw 'Profile changed.' }
            Remove-VpnConnection -Name $config.name -Force -ErrorAction Stop
        }
        default { throw 'Unknown profile operation.' }
    }
} catch {
    if ($null -ne $createdGuid) {
        try {
            $current = Find-Profile
            if ($null -ne $current -and [string]$current.Guid -eq $createdGuid) {
                Remove-VpnConnection -Name $config.name -Force -ErrorAction Stop
            }
        } catch { }
    }
    # Never forward arbitrary provider diagnostics, which may include user information.
    [Console]::Error.WriteLine('Windows profile operation failed; inspect the profile and ownership record before retrying.')
    exit 1
}
