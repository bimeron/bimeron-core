//go:build windows

package windowsnet

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type physicalRoute struct {
	index   uint32
	gateway netip.Addr
	metric  uint64
}

func sockaddrAddr(raw windows.RawSockaddrInet) (netip.Addr, bool) {
	switch raw.Family {
	case windows.AF_INET:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(&raw)).Addr), true
	case windows.AF_INET6:
		a := (*windows.RawSockaddrInet6)(unsafe.Pointer(&raw))
		return netip.AddrFrom16(a.Addr).WithZone(""), true
	default:
		return netip.Addr{}, false
	}
}

func choosePhysical(routes []physicalRoute) (physicalRoute, bool) {
	if len(routes) == 0 {
		return physicalRoute{}, false
	}
	sort.Slice(routes, func(i, j int) bool {
		a, b := routes[i], routes[j]
		if a.metric != b.metric {
			return a.metric < b.metric
		}
		if a.index != b.index {
			return a.index < b.index
		}
		return a.gateway.Compare(b.gateway) < 0
	})
	return routes[0], true
}

func nativeObserve(ctx context.Context, name string, startup bool) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	var interfaces *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormalWithoutStatistics, &interfaces); err != nil {
		return Snapshot{}, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(interfaces))
	physical := make(map[uint32]bool)
	foundTunnel := false
	for _, row := range unsafe.Slice(&interfaces.Table[0], interfaces.NumEntries) {
		if strings.EqualFold(windows.UTF16ToString(row.Alias[:]), name) {
			foundTunnel = true
		}
		// MIB_IF_ROW2.InterfaceAndOperStatusFlags bit 0 is HardwareInterface.
		if row.OperStatus == windows.IfOperStatusUp && row.InterfaceAndOperStatusFlags&1 != 0 {
			physical[row.InterfaceIndex] = true
		}
	}
	if startup && foundTunnel {
		return Snapshot{}, fmt.Errorf("Tunnel name is already in use")
	}
	if !startup && !foundTunnel {
		return Snapshot{}, fmt.Errorf("Tunnel adapter disappeared")
	}
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil {
		return Snapshot{}, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	var v4, v6 []physicalRoute
	for _, row := range table.Rows() {
		if !physical[row.InterfaceIndex] || row.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		gateway, ok := sockaddrAddr(row.NextHop)
		if !ok || gateway.Is4() && gateway.IsUnspecified() {
			continue
		}
		family := uint16(windows.AF_INET6)
		if row.DestinationPrefix.Prefix.Family == windows.AF_INET {
			family = windows.AF_INET
		} else if row.DestinationPrefix.Prefix.Family != windows.AF_INET6 {
			continue
		}
		ipif := windows.MibIpInterfaceRow{Family: family, InterfaceIndex: row.InterfaceIndex}
		if err := windows.GetIpInterfaceEntry(&ipif); err != nil {
			return Snapshot{}, err
		}
		candidate := physicalRoute{index: row.InterfaceIndex, gateway: gateway, metric: uint64(row.Metric) + uint64(ipif.Metric)}
		if family == windows.AF_INET {
			v4 = append(v4, candidate)
		} else {
			v6 = append(v6, candidate)
		}
	}
	primary, ok := choosePhysical(v4)
	if !ok {
		return Snapshot{}, fmt.Errorf("No physical IPv4 default gateway found")
	}
	s := Snapshot{IPv4: int(primary.index), Gateway4: primary.gateway.String()}
	if secondary, ok := choosePhysical(v6); ok {
		s.IPv6, s.Gateway6 = int(secondary.index), secondary.gateway.String()
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	adapters, err := adapterAddresses()
	if err != nil {
		return Snapshot{}, err
	}
	var addresses []string
	for a := adapters; a != nil; a = a.Next {
		if int(a.IfIndex) != s.IPv4 && (s.IPv6 == 0 || int(a.Ipv6IfIndex) != s.IPv6) {
			continue
		}
		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			if u.DadState == windows.IpDadStatePreferred {
				if ip := u.Address.IP(); ip != nil {
					index := a.IfIndex
					if ip.To4() == nil {
						index = a.Ipv6IfIndex
					}
					if int(index) == s.IPv4 || s.IPv6 > 0 && int(index) == s.IPv6 {
						addresses = append(addresses, fmt.Sprintf("%d:%s/%d", index, ip.String(), u.OnLinkPrefixLength))
					}
				}
			}
		}
		if int(a.IfIndex) == s.IPv4 {
			seen := make(map[string]bool)
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				if ip := d.Address.IP(); ip != nil && ip.To4() != nil && !seen[ip.String()] {
					seen[ip.String()] = true
					s.DNS = append(s.DNS, ip.String())
				}
			}
		}
	}
	sort.Strings(addresses)
	sort.Strings(s.DNS)
	s.Addresses = strings.Join(addresses, ",")
	return s, nil
}

func adapterAddresses() (*windows.IpAdapterAddresses, error) {
	size := uint32(15 * 1024)
	for range 3 {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, err
		}
		return first, nil
	}
	return nil, fmt.Errorf("adapter address table changed repeatedly")
}
