//go:build windows

package windowsnet

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Read-only smoke test for a workstation with a connected Bimeron adapter.
func TestNativeObserveConnected(t *testing.T) {
	if os.Getenv("BIMERON_TEST_NATIVE_OBSERVE") != "1" {
		t.Skip("set BIMERON_TEST_NATIVE_OBSERVE=1 on a connected Windows host")
	}
	name := os.Getenv("BIMERON_TEST_ADAPTER_NAME")
	if name == "" {
		t.Fatal("set BIMERON_TEST_ADAPTER_NAME to the connected adapter alias")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := nativeObserve(ctx, name, false)
	if err != nil {
		t.Fatal(err)
	}
	if s.IPv4 <= 0 || s.Gateway4 == "" || s.Addresses == "" {
		t.Fatalf("incomplete physical path: %+v", s)
	}
	const baseline = `
$physical = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object ifIndex)
$route = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -in $physical -and $_.NextHop -ne '0.0.0.0' } | Sort-Object @{Expression={ $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric }},InterfaceIndex,NextHop)[0]
@{index=[int]$route.InterfaceIndex;gateway=[string]$route.NextHop} | ConvertTo-Json -Compress`
	out, err := executeScript(ctx, Config{}, baseline)
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		Index   int    `json:"index"`
		Gateway string `json:"gateway"`
	}
	if err := json.Unmarshal(out, &expected); err != nil {
		t.Fatal(err)
	}
	if s.IPv4 != expected.Index || s.Gateway4 != expected.Gateway {
		t.Fatalf("native physical path differs from PowerShell: index %d/%d gateway %s/%s", s.IPv4, expected.Index, s.Gateway4, expected.Gateway)
	}
}
