//go:build windows

package windowsnet

import (
	"context"
	"encoding/json"
	"net/netip"
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
func TestSetupOwnsOnlyDNS(t *testing.T) {
	body := `$result = & {` + script + `} | ConvertFrom-Json
 @{routes=@($global:routes | ForEach-Object {$_.DestinationPrefix});dns=@($global:rules | ForEach-Object {$_.Comment});setup=$result} | ConvertTo-Json -Compress
 `
	result := mocked(t, Config{Action: "setup", Name: "Bimeron", Tag: "BimeronCore:test", Index: 42}, body)
	if len(result["routes"].([]any)) != 1 || len(result["dns"].([]any)) != 2 {
		t.Fatalf("unexpected setup: %v", result)
	}
	setup := result["setup"].(map[string]any)
	if setup["index"] != float64(42) || setup["interfaceMs"] == nil || setup["dnsMs"] == nil {
		t.Fatalf("missing setup timings: %v", setup)
	}
}
func TestSetupFailureRollsBackOwnedDNS(t *testing.T) {
	body := `function Clear-DnsClientCache { throw 'simulated cache failure' }
 $caught=$false
 try { $null = & {` + script + `} } catch { $caught=$true }
 @{caught=$caught;removed=@($global:removedDns)} | ConvertTo-Json -Compress
 `
	result := mocked(t, Config{Action: "setup", Name: "Bimeron", Tag: "BimeronCore:test", Index: 42}, body)
	if result["caught"] != true {
		t.Fatal("setup failure swallowed")
	}
	if len(result["removed"].([]any)) != 1 || result["removed"].([]any)[0] != "our-rule" {
		t.Fatalf("rollback did not remove owned DNS: %v", result)
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

func TestCleanupReportsDNSFailureAndClearsCache(t *testing.T) {
	body := `function Remove-DnsClientNrptRule { throw 'simulated DNS error' }
	$global:cacheClears=0
	function Clear-DnsClientCache { $global:cacheClears++ }
 $global:rules += [pscustomobject]@{Name='our-rule';Comment='BimeronCore:test'}
 $caught=$false
 try { $null = & {` + script + `} } catch { $caught=$true }
	@{caught=$caught;cacheClears=$global:cacheClears} | ConvertTo-Json -Compress`
	result := mocked(t, Config{Action: "cleanup", Name: "Bimeron", Tag: "BimeronCore:test", Index: 42}, body)
	if result["caught"] != true || result["cacheClears"] != float64(1) {
		t.Fatalf("cleanup stopped after DNS error: %v", result)
	}
}

func TestChoosePhysicalRoute(t *testing.T) {
	r, ok := choosePhysical([]physicalRoute{{index: 98, gateway: netip.MustParseAddr("10.0.0.1"), metric: 50}, {index: 29, gateway: netip.MustParseAddr("192.168.1.1"), metric: 50}})
	if !ok || r.index != 29 {
		t.Fatalf("wrong physical route: %v", r)
	}
}

func TestInspectRecoversOwnedDnsBeforeCheckingConflicts(t *testing.T) {
	body := `
 $global:rules = @([pscustomobject]@{Name='stale-rule';Comment='BimeronCore:stale'})
 $global:cacheClears = 0
 function Clear-DnsClientCache { $global:cacheClears++ }
 function Get-NetAdapter { param($Name,[switch]$Physical) if ($Physical) { [pscustomobject]@{ifIndex=29;Status='Up'} } }
 function Get-NetRoute { param($AddressFamily) if ($AddressFamily -eq 'IPv4') { [pscustomobject]@{InterfaceIndex=29;DestinationPrefix='0.0.0.0/0';NextHop='192.168.1.1';RouteMetric=25} } }
 function Get-NetIPInterface { [pscustomobject]@{InterfaceMetric=25} }
 function Get-NetIPAddress { [pscustomobject]@{InterfaceIndex=29;IPAddress='192.168.1.2';PrefixLength=24;AddressState='Preferred'} }
	$null = & {` + script + `}
	@{removed=@($global:removedDns);cacheClears=$global:cacheClears} | ConvertTo-Json -Compress`
	r := mocked(t, Config{Action: "inspect", Name: "Bimeron"}, body)
	if r["cacheClears"] != float64(1) || len(r["removed"].([]any)) != 1 || r["removed"].([]any)[0] != "stale-rule" {
		t.Fatalf("inspect did not recover owned DNS: %v", r)
	}
}

func TestInspectKeepsForeignDnsPolicy(t *testing.T) {
	body := `
 $global:rules += [pscustomobject]@{Name='stale-rule';Comment='BimeronCore:stale'}
 function Get-NetAdapter { $null }
 $caught = $false
 try { $null = & {` + script + `} } catch { $caught = $_.Exception.Message -like 'Existing NRPT rules*' }
 @{caught=$caught;removed=@($global:removedDns)} | ConvertTo-Json -Compress`
	r := mocked(t, Config{Action: "inspect", Name: "Bimeron"}, body)
	if r["caught"] != true || len(r["removed"].([]any)) != 1 || r["removed"].([]any)[0] != "stale-rule" {
		t.Fatalf("inspect changed foreign DNS policy: %v", r)
	}
}
