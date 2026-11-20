//go:build windows

package core

import (
	"errors"
	"net"
	"os"
	"testing"

	"bimeron/internal/windowsnet"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"golang.org/x/sys/windows"
	winTun "golang.zx2c4.com/wireguard/tun"
)

// TestLiveRequestedGUIDIdentifiesTunnel creates a real Wintun adapter with a
// requested GUID and resolves it through that GUID, as Open does. It needs an
// elevated session and wintun.dll next to the test binary.
func TestLiveRequestedGUIDIdentifiesTunnel(t *testing.T) {
	if os.Getenv("BIMERON_WINTUN_LIVE") != "1" {
		t.Skip("set BIMERON_WINTUN_LIVE=1 in an elevated session with wintun.dll next to the test binary")
	}
	const name = "BimeronIdTest"
	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	winTun.WintunStaticRequestedGUID = &guid
	d, err := tun.Open(name, 1420)
	winTun.WintunStaticRequestedGUID = nil
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	index, err := windowsnet.TunnelInterface(guid, name)
	if err != nil {
		t.Fatal(err)
	}
	if iface, err := net.InterfaceByIndex(index); err != nil || iface.Name != name {
		t.Fatal("GUID resolved to another interface", iface, err)
	}
	if _, err := windowsnet.TunnelInterface(guid, "BimeronOther"); !errors.Is(err, windowsnet.ErrTunnelNameTaken) {
		t.Fatal("name mismatch not reported", err)
	}
}
