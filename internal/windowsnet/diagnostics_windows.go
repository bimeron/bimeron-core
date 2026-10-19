//go:build windows

package windowsnet

import (
	"context"
	"encoding/json"
)

type Diagnostics struct {
	Service        string `json:"service"`
	Adapters       int    `json:"adapters"`
	Up             int    `json:"up"`
	Routes4        int    `json:"routes4"`
	Routes6        int    `json:"routes6"`
	DNSRules       int    `json:"dns_rules"`
	TunnelDNSRules int    `json:"tunnel_dns_rules"`
}

// InspectDiagnostics reads only aggregate metadata. Addresses, names, rules and
// command diagnostics are never returned to the caller.
func InspectDiagnostics(ctx context.Context) (Diagnostics, error) {
	const body = `
$service = Get-Service -Name BimeronCore -ErrorAction SilentlyContinue
$addresses = @(Get-NetIPAddress -IPAddress '198.18.0.1' -ErrorAction SilentlyContinue)
$indices = @($addresses | Select-Object -ExpandProperty InterfaceIndex -Unique)
$adapters = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceIndex -in $indices })
$routes4 = @(Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.InterfaceIndex -in $indices -and $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') })
$routes6 = @(Get-NetRoute -AddressFamily IPv6 | Where-Object { $_.InterfaceIndex -in $indices -and $_.DestinationPrefix -in @('::/1','8000::/1') })
$dns = @(Get-DnsClientNrptRule | Where-Object { $_.Comment -like 'BimeronCore:*' })
$tunnelDNS = @($dns | Where-Object { '198.18.0.2' -in $_.NameServers })
$state = 'not_installed'; if ($null -ne $service) { $state = $service.Status.ToString().ToLowerInvariant() }
@{ service=$state; adapters=$adapters.Count; up=@($adapters | Where-Object Status -eq 'Up').Count; routes4=$routes4.Count; routes6=$routes6.Count; dns_rules=$dns.Count; tunnel_dns_rules=$tunnelDNS.Count } | ConvertTo-Json -Compress
`
	b, err := executeScript(ctx, Config{}, body)
	if err != nil {
		return Diagnostics{}, err
	}
	var d Diagnostics
	err = json.Unmarshal(b, &d)
	return d, err
}
