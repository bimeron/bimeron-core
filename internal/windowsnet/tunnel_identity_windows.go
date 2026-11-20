//go:build windows

package windowsnet

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var convertGUIDToLUID = ipHelper.NewProc("ConvertInterfaceGuidToLuid")

// ErrTunnelNameTaken reports a created tunnel adapter that does not hold the
// configured name, because another interface took it first.
var ErrTunnelNameTaken = errors.New("Tunnel name is already in use")

// TunnelInterface returns the interface index of the adapter that Wintun
// created with guid, found through its LUID, and checks that the adapter
// holds name. The tunnel is never looked up by name, so an interface that
// took the name in the meantime is reported instead of being configured.
func TunnelInterface(guid windows.GUID, name string) (int, error) {
	var luid uint64
	if code, _, _ := convertGUIDToLUID.Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&luid))); code != 0 {
		return 0, fmt.Errorf("tunnel adapter not found: %w", syscall.Errno(code))
	}
	row := windows.MibIfRow2{InterfaceLuid: luid}
	if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &row); err != nil {
		return 0, fmt.Errorf("tunnel adapter not found: %w", err)
	}
	return checkTunnelRow(windows.UTF16ToString(row.Alias[:]), row.InterfaceGuid, int(row.InterfaceIndex), guid, name)
}

// checkTunnelRow accepts the interface row of the created adapter only if it
// is that adapter and holds exactly the configured name.
func checkTunnelRow(alias string, rowGUID windows.GUID, index int, guid windows.GUID, name string) (int, error) {
	if rowGUID != guid || index <= 0 {
		return 0, fmt.Errorf("tunnel adapter identity changed")
	}
	if alias != name {
		return 0, ErrTunnelNameTaken
	}
	return index, nil
}
