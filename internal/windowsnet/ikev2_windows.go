//go:build windows

package windowsnet

import (
	"context"
	_ "embed"
	"errors"
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed ikev2_dns.ps1
var nativeDNSScript string

type VPNNetwork struct {
	Index uint32
	LUID  uint64
	DNS   []string
}

// ObserveVPN reads a connected PPP adapter; it never changes the RAS profile.
func ObserveVPN(ctx context.Context, name string) (VPNNetwork, error) {
	if err := ctx.Err(); err != nil {
		return VPNNetwork{}, err
	}
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormalWithoutStatistics, &table); err != nil {
		return VPNNetwork{}, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	var result VPNNetwork
	for _, row := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		if strings.EqualFold(windows.UTF16ToString(row.Alias[:]), name) && row.Type == 23 && row.OperStatus == windows.IfOperStatusUp {
			result.Index, result.LUID = row.InterfaceIndex, row.InterfaceLuid
		}
	}
	if result.Index == 0 || result.LUID == 0 {
		return VPNNetwork{}, errors.New("native VPN interface unavailable")
	}
	head, err := adapterAddresses()
	if err != nil {
		return VPNNetwork{}, err
	}
	for a := head; a != nil; a = a.Next {
		if a.IfIndex != result.Index || a.Luid != result.LUID {
			continue
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			if d.Address.Sockaddr == nil {
				continue
			}
			address, ok := netip.AddrFromSlice(d.Address.IP())
			if !ok || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
				continue
			}
			address = address.Unmap()
			result.DNS = append(result.DNS, address.String())
		}
	}
	if len(result.DNS) == 0 {
		return VPNNetwork{}, errors.New("native VPN DNS unavailable")
	}
	return result, nil
}

func CheckIKEv2DNS(ctx context.Context) error {
	_, err := executeScript(ctx, Config{Action: "inspect"}, nativeDNSScript)
	return err
}
func ConfigureIKEv2DNS(ctx context.Context, tag string, servers []string) error {
	for _, s := range servers {
		ip, e := netip.ParseAddr(s)
		if e != nil || !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return errors.New("invalid native DNS address")
		}
	}
	if len(servers) == 0 {
		return errors.New("missing native DNS servers")
	}
	_, err := executeScript(ctx, Config{Action: "setup", Tag: tag, DNS: servers}, nativeDNSScript)
	return err
}
func CleanupIKEv2DNS(ctx context.Context, tag string, servers []string) error {
	_, err := executeScript(ctx, Config{Action: "cleanup", Tag: tag, DNS: servers}, nativeDNSScript)
	if err != nil && strings.Contains(err.Error(), "Owned DNS policy changed") {
		return errors.New("ikev2_owned_dns_policy_modified")
	}
	return err
}
func RecoverIKEv2DNS(ctx context.Context) error {
	_, err := executeScript(ctx, Config{Action: "recover"}, nativeDNSScript)
	return err
}
