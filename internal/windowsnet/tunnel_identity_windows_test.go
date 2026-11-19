//go:build windows

package windowsnet

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// Only the created adapter, holding exactly the configured name, is accepted.
func TestCheckTunnelRow(t *testing.T) {
	created := windows.GUID{Data1: 1}
	other := windows.GUID{Data1: 2}
	if index, err := checkTunnelRow("Bimeron", created, 17, created, "Bimeron"); err != nil || index != 17 {
		t.Fatal(index, err)
	}
	if _, err := checkTunnelRow("Bimeron", other, 17, created, "Bimeron"); err == nil || errors.Is(err, ErrTunnelNameTaken) {
		t.Fatal("another adapter accepted", err)
	}
	if _, err := checkTunnelRow("Bimeron 2", created, 17, created, "Bimeron"); !errors.Is(err, ErrTunnelNameTaken) {
		t.Fatal("renamed adapter accepted", err)
	}
	if _, err := checkTunnelRow("Bimeron", created, 0, created, "Bimeron"); err == nil {
		t.Fatal("invalid index accepted")
	}
}

// An unknown GUID resolves to no interface.
func TestTunnelInterfaceUnknownGUID(t *testing.T) {
	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TunnelInterface(guid, "Bimeron"); err == nil {
		t.Fatal("unknown adapter resolved")
	}
}
