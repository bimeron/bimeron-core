//go:build windows

package windowsnet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const mockCmdlets = `
$global:routes = @([pscustomobject]@{DestinationPrefix='192.168.0.0/16';InterfaceIndex=42})
$global:rules = @([pscustomobject]@{Name='other-rule';Comment='OtherSoftware'})
$global:removedDns = @()
$global:removedRoutes = @()
function Get-NetAdapter { [pscustomobject]@{ifIndex=42;Name='Bimeron'} }
function Set-NetIPInterface {}
function New-NetIPAddress {}
function Set-DnsClient {}
function Set-DnsClientServerAddress {}
function Get-DnsClientServerAddress { [pscustomobject]@{ServerAddresses=@('192.168.1.1')} }
function Clear-DnsClientCache {}
function New-NetRoute {
 param($InterfaceIndex,$DestinationPrefix,$NextHop,$RouteMetric,$PolicyStore)
 if ($global:failRoute -and $DestinationPrefix -eq '::/1') { throw 'simulated route failure' }
 $global:routes += [pscustomobject]@{DestinationPrefix=$DestinationPrefix;InterfaceIndex=$InterfaceIndex}
}
function Get-NetRoute { $global:routes }
function Remove-NetRoute {
 [CmdletBinding(SupportsShouldProcess)]param([Parameter(ValueFromPipeline)]$InputObject)
 process { $global:removedRoutes += $InputObject.DestinationPrefix }
}
function Add-DnsClientNrptRule {
 param($Namespace,$NameServers,$Comment)
 $global:rules += [pscustomobject]@{Name='our-rule';Comment=$Comment}
}
function Get-DnsClientNrptRule { $global:rules }
function Remove-DnsClientNrptRule {
 param($Name,[switch]$Force)
 $global:removedDns += $Name
}
`

func mocked(t *testing.T, c Config, extra string) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	b, err := executeScript(ctx, c, mockCmdlets+extra)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatalf("bad mock result: %s", b)
	}
	return result
}
func TestSetupUsesOwnedRoutes(t *testing.T) {
	body := `$null = & {` + script + `}
 @{routes=@($global:routes | ForEach-Object {$_.DestinationPrefix});dns=@($global:rules | ForEach-Object {$_.Comment})} | ConvertTo-Json -Compress
 `
	result := mocked(t, Config{Action: "setup", Name: "Bimeron", Tag: "BimeronCore:test", Index: 42}, body)
	if len(result["routes"].([]any)) != 5 || len(result["dns"].([]any)) != 2 {
		t.Fatalf("unexpected setup: %v", result)
	}
}
func TestSetupFailureRollsBackOnlyOwnRoutes(t *testing.T) {
	body := `$global:failRoute=$true
 $caught=$false
 try { $null = & {` + script + `} } catch { $caught=$true }
 @{caught=$caught;removed=@($global:removedRoutes)} | ConvertTo-Json -Compress
 `
	result := mocked(t, Config{Action: "setup", Name: "Bimeron", Tag: "BimeronCore:test", Index: 42}, body)
	if result["caught"] != true {
		t.Fatal("setup failure swallowed")
	}
	removed := result["removed"].([]any)
	if len(removed) != 2 {
		t.Fatalf("rollback did not remove both IPv4 routes: %v", result)
	}
	for _, p := range removed {
		if p == "192.168.0.0/16" {
			t.Fatal("removed preexisting route")
		}
	}
}
func TestCleanupPreservesOtherDnsRules(t *testing.T) {
	body := `$global:rules += [pscustomobject]@{Name='our-rule';Comment='BimeronCore:test'}
 $null = & {` + script + `}
 @{removed=@($global:removedDns)} | ConvertTo-Json -Compress
 `
	result := mocked(t, Config{Action: "cleanup", Name: "Bimeron", Tag: "BimeronCore:test", Index: 42}, body)
	removed := result["removed"].([]any)
	if len(removed) != 1 || removed[0] != "our-rule" {
		t.Fatalf("wrong DNS cleanup: %v", result)
	}
}
func TestNetworkCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := executeScript(ctx, Config{}, "throw 'must not run'")
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("ignored cancellation: %v", err)
	}
}

func TestCleanupContinuesAfterDNSFailure(t *testing.T) {
	body := `function Remove-DnsClientNrptRule { throw 'simulated DNS error' }
 $global:rules += [pscustomobject]@{Name='our-rule';Comment='BimeronCore:test'}
 $global:routes += [pscustomobject]@{DestinationPrefix='0.0.0.0/1';InterfaceIndex=42}
 $caught=$false
 try { $null = & {` + script + `} } catch { $caught=$true }
 @{caught=$caught;removed=@($global:removedRoutes)} | ConvertTo-Json -Compress`
	result := mocked(t, Config{Action: "cleanup", Name: "Bimeron", Tag: "BimeronCore:test", Index: 42}, body)
	if result["caught"] != true || len(result["removed"].([]any)) != 1 || result["removed"].([]any)[0] != "0.0.0.0/1" {
		t.Fatalf("cleanup stopped after DNS error: %v", result)
	}
}

func TestObserveChoosesPhysicalDefaults(t *testing.T) {
	body := `
 function Get-NetAdapter { param($Name,[switch]$Physical) if ($Physical) { [pscustomobject]@{ifIndex=29;Status='Up'} } else { [pscustomobject]@{ifIndex=42;Status='Up'} } }
 function Get-NetRoute { param($AddressFamily,$DestinationPrefix,$PolicyStore)
   if ($AddressFamily -eq 'IPv4') {
     [pscustomobject]@{InterfaceIndex=98;DestinationPrefix='0.0.0.0/0';NextHop='10.0.0.1';RouteMetric=0}
     [pscustomobject]@{InterfaceIndex=29;DestinationPrefix='0.0.0.0/0';NextHop='192.168.1.1';RouteMetric=25}
   } else {
     [pscustomobject]@{InterfaceIndex=98;DestinationPrefix='::/0';NextHop='::';RouteMetric=0}
   }
 }
 function Get-NetIPInterface { [pscustomobject]@{InterfaceMetric=25} }
 function Get-NetIPAddress {
   [pscustomobject]@{InterfaceIndex=29;IPAddress='192.168.1.2';PrefixLength=24;AddressState='Preferred'}
   [pscustomobject]@{InterfaceIndex=98;IPAddress='10.0.0.2';PrefixLength=24;AddressState='Preferred'}
 }
 ` + script
	r := mocked(t, Config{Action: "observe", Name: "Bimeron"}, body)
	if r["ipv4"] != float64(29) || r["ipv6"] != float64(0) || r["gateway4"] != "192.168.1.1" || r["addresses"] != "29:192.168.1.2/24" {
		t.Fatalf("wrong outbound path: %v", r)
	}
}
