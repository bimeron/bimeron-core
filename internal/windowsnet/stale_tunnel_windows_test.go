//go:build windows

package windowsnet

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/sys/windows"
)

func TestStaleOwnTunnel(t *testing.T) {
	guid := windows.GUID{Data1: 0x0916f5b5, Data2: 0x9443, Data3: 0x4c94, Data4: [8]byte{0xb9, 0xaf, 0x4f, 0x3d, 0x23, 0xfe, 0xbe, 0x64}}
	stale := tunnelInterface{
		Alias:         "Bimeron",
		Description:   "Bimeron Tunnel",
		Type:          ifTypePropVirtual,
		Oper:          uint32(windows.IfOperStatusNotPresent),
		GUID:          guid,
		PnPInstanceID: `SWD\Wintun\{0916F5B5-9443-4C94-B9AF-4F3D23FEBE64}`,
	}
	tests := []struct {
		name   string
		change func(*tunnelInterface)
		want   bool
	}{
		{"absent device node", func(*tunnelInterface) {}, true},
		{"case-insensitive alias and instance", func(t *tunnelInterface) {
			t.Alias = "BIMERON"
			t.PnPInstanceID = `SWD\WINTUN\{0916f5b5-9443-4c94-b9af-4f3d23febe64}`
		}, true},
		{"down after removed device node", func(t *tunnelInterface) { t.Oper = uint32(windows.IfOperStatusDown) }, true},
		{"numbered description", func(t *tunnelInterface) { t.Description = "Bimeron Tunnel #2" }, true},
		{"present device node", func(t *tunnelInterface) { t.DevicePresent = true }, false},
		{"interface up", func(t *tunnelInterface) { t.Oper = uint32(windows.IfOperStatusUp) }, false},
		{"other name", func(t *tunnelInterface) { t.Alias = "Bimeron 2" }, false},
		{"foreign Wintun tunnel type", func(t *tunnelInterface) { t.Description = "WireGuard Tunnel" }, false},
		{"malformed description suffix", func(t *tunnelInterface) { t.Description = "Bimeron Tunnel #x" }, false},
		{"empty description number", func(t *tunnelInterface) { t.Description = "Bimeron Tunnel #" }, false},
		{"description prefix only", func(t *tunnelInterface) { t.Description = "Bimeron Tunnels" }, false},
		{"not a virtual interface", func(t *tunnelInterface) { t.Type = 6 }, false},
		{"not created by Wintun", func(t *tunnelInterface) { t.PnPInstanceID = `ROOT\NET\0000` }, false},
		{"device of another interface", func(t *tunnelInterface) { t.PnPInstanceID = `SWD\Wintun\{00000000-0000-0000-0000-000000000000}` }, false},
		{"no connection record", func(t *tunnelInterface) { t.PnPInstanceID = "" }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := stale
			test.change(&candidate)
			if got := staleOwnTunnel(candidate, "Bimeron"); got != test.want {
				t.Fatalf("staleOwnTunnel = %v, want %v", got, test.want)
			}
		})
	}
}

func TestReclaimStaleTunnelUnusedName(t *testing.T) {
	var random [6]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	guid, err := ReclaimStaleTunnel("BimeronTest" + hex.EncodeToString(random[:]))
	if err != nil || guid != nil {
		t.Fatalf("ReclaimStaleTunnel = %v, %v; want nil, nil", guid, err)
	}
}
