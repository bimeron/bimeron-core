//go:build windows

package windowsnet

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// TunnelType is the Wintun tunnel type of Bimeron adapters. Wintun describes
// such adapters as "<TunnelType> Tunnel".
const TunnelType = "Bimeron"

const (
	ifTypePropVirtual = 53
	wintunEnumerator  = `SWD\Wintun`
	netClassKey       = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\`
)

var netClassGUID = windows.GUID{Data1: 0x4d36e972, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}

// tunnelInterface is what Windows still records for an interface that holds
// the tunnel name.
type tunnelInterface struct {
	Alias         string
	Description   string
	Type          uint32
	Oper          uint32
	GUID          windows.GUID
	PnPInstanceID string // Network class Connection\PnPInstanceId
	DevicePresent bool   // a started device node backs the interface
}

// staleOwnTunnel reports whether t is a Bimeron Wintun interface named name
// that no device backs. A Wintun device disappears with its process but its
// device node and interface alias persist, also across reboots, after an
// unclean exit such as a killed process or a power loss.
func staleOwnTunnel(t tunnelInterface, name string) bool {
	if !strings.EqualFold(t.Alias, name) || t.Type != ifTypePropVirtual || t.Oper == uint32(windows.IfOperStatusUp) || t.DevicePresent {
		return false
	}
	if !strings.EqualFold(t.PnPInstanceID, wintunEnumerator+`\`+t.GUID.String()) {
		return false
	}
	// Windows appends " #N" when several adapters share a description.
	description, ok := strings.CutPrefix(t.Description, TunnelType+" Tunnel")
	if !ok {
		return false
	}
	if description == "" {
		return true
	}
	number, ok := strings.CutPrefix(description, " #")
	return ok && number != "" && strings.Trim(number, "0123456789") == ""
}

// wintunDevice finds the device node of the Wintun adapter with guid,
// including a node that is no longer present. The caller closes set when found.
func wintunDevice(guid windows.GUID) (set windows.DevInfo, data *windows.DevInfoData, found bool, err error) {
	set, err = windows.SetupDiGetClassDevsEx(&netClassGUID, wintunEnumerator, 0, 0, 0, "")
	if err != nil {
		return 0, nil, false, err
	}
	want := wintunEnumerator + `\` + guid.String()
	for i := 0; ; i++ {
		data, err = set.EnumDeviceInfo(i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			break
		}
		if err != nil {
			continue
		}
		if id, idErr := set.DeviceInstanceID(data); idErr == nil && strings.EqualFold(id, want) {
			return set, data, true, nil
		}
	}
	set.Close()
	return 0, nil, false, nil
}

func describeTunnel(row *windows.MibIfRow2) (tunnelInterface, error) {
	t := tunnelInterface{
		Alias:       windows.UTF16ToString(row.Alias[:]),
		Description: windows.UTF16ToString(row.Description[:]),
		Type:        row.Type,
		Oper:        uint32(row.OperStatus),
		GUID:        row.InterfaceGuid,
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, netClassKey+t.GUID.String()+`\Connection`, registry.QUERY_VALUE)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return t, nil
	}
	if err != nil {
		return t, err
	}
	t.PnPInstanceID, _, err = key.GetStringValue("PnPInstanceId")
	key.Close()
	if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return t, err
	}
	set, data, found, err := wintunDevice(t.GUID)
	if err != nil || !found {
		return t, err
	}
	defer set.Close()
	var status, problem uint32
	t.DevicePresent = windows.CM_Get_DevNode_Status(&status, &problem, data.DevInst, 0) == nil
	return t, nil
}

// staleTunnelRow reports whether row is a stale Bimeron interface named name.
// Inspection errors count as a conflict.
func staleTunnelRow(row *windows.MibIfRow2, name string) bool {
	t, err := describeTunnel(row)
	return err == nil && staleOwnTunnel(t, name)
}

// ReclaimStaleTunnel prepares the reuse of a stale Bimeron Wintun interface
// that still holds name. It removes the interface's absent device node and
// returns its GUID; Wintun then recreates the adapter as the same interface,
// which keeps the name, and a clean close removes it completely. It returns
// nil when no interface holds name and an error when another interface does.
// The caller holds the session lock.
func ReclaimStaleTunnel(name string) (*windows.GUID, error) {
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormalWithoutStatistics, &table); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	for _, row := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		if !strings.EqualFold(windows.UTF16ToString(row.Alias[:]), name) {
			continue
		}
		t, err := describeTunnel(&row)
		if err != nil {
			return nil, err
		}
		if !staleOwnTunnel(t, name) {
			return nil, fmt.Errorf("Tunnel name is already in use")
		}
		guid := t.GUID
		return &guid, removeAbsentDevice(guid)
	}
	return nil, nil
}

func removeAbsentDevice(guid windows.GUID) error {
	set, data, found, err := wintunDevice(guid)
	if err != nil || !found {
		return err
	}
	defer set.Close()
	var status, problem uint32
	if windows.CM_Get_DevNode_Status(&status, &problem, data.DevInst, 0) == nil {
		return fmt.Errorf("Tunnel name is already in use")
	}
	params := windows.RemoveDeviceParams{
		ClassInstallHeader: *windows.MakeClassInstallHeader(windows.DIF_REMOVE),
		Scope:              windows.DI_REMOVEDEVICE_GLOBAL,
	}
	if err := set.SetClassInstallParams(data, &params.ClassInstallHeader, uint32(unsafe.Sizeof(params))); err != nil {
		return err
	}
	return set.CallClassInstaller(windows.DIF_REMOVE, data)
}
