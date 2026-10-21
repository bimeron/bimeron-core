//go:build windows

package windowsnet

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")
var createAddress = ipHelper.NewProc("CreateUnicastIpAddressEntry")
var deleteAddress = ipHelper.NewProc("DeleteUnicastIpAddressEntry")
var createRoute = ipHelper.NewProc("CreateIpForwardEntry2")
var deleteRoute = ipHelper.NewProc("DeleteIpForwardEntry2")
var initializeAddress = ipHelper.NewProc("InitializeUnicastIpAddressEntry")
var initializeRoute = ipHelper.NewProc("InitializeIpForwardEntry")

type nativeResources struct {
	adapter   windows.GUID
	index     uint32
	addresses []windows.MibUnicastIpAddressRow
	routes    []windows.MibIpForwardRow2
}

var ownedNative = struct {
	sync.Mutex
	byTag map[string]*nativeResources
}{byTag: make(map[string]*nativeResources)}

func callIPHelper(proc *windows.LazyProc, row unsafe.Pointer) error {
	code, _, _ := proc.Call(uintptr(row))
	if code != 0 {
		return syscall.Errno(code)
	}
	return nil
}

func ipSockaddr(ip netip.Addr) windows.RawSockaddrInet {
	var raw windows.RawSockaddrInet
	if ip.Is4() {
		a := (*windows.RawSockaddrInet4)(unsafe.Pointer(&raw))
		a.Family, a.Addr = windows.AF_INET, ip.As4()
	} else {
		a := (*windows.RawSockaddrInet6)(unsafe.Pointer(&raw))
		a.Family, a.Addr = windows.AF_INET6, ip.As16()
	}
	return raw
}

func nativeBegin(c Config) error {
	if c.Index <= 0 || c.Tag == "" {
		return fmt.Errorf("invalid native network owner")
	}
	adapter := windows.MibIfRow2{InterfaceIndex: uint32(c.Index)}
	if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &adapter); err != nil {
		return err
	}
	if windows.UTF16ToString(adapter.Alias[:]) != c.Name {
		return fmt.Errorf("tunnel adapter identity changed")
	}
	ownedNative.Lock()
	defer ownedNative.Unlock()
	if ownedNative.byTag[c.Tag] != nil {
		return fmt.Errorf("native network owner already exists")
	}
	ownedNative.byTag[c.Tag] = &nativeResources{adapter: adapter.InterfaceGuid, index: uint32(c.Index)}
	return nil
}

func nativeAddAddresses(c Config) error {
	for _, spec := range []string{"198.18.0.1/30", "fd69:726f:7574::1/128"} {
		prefix := netip.MustParsePrefix(spec)
		var row windows.MibUnicastIpAddressRow
		initializeAddress.Call(uintptr(unsafe.Pointer(&row)))
		row.Address = *(*windows.RawSockaddrInet6)(unsafe.Pointer(&[]windows.RawSockaddrInet{ipSockaddr(prefix.Addr())}[0]))
		row.InterfaceIndex = uint32(c.Index)
		row.PrefixOrigin = windows.IpPrefixOriginManual
		row.SuffixOrigin = windows.NlsoManual
		row.OnLinkPrefixLength = uint8(prefix.Bits())
		if err := callIPHelper(createAddress, unsafe.Pointer(&row)); err != nil {
			return fmt.Errorf("create %s: %w", spec, err)
		}
		ownedNative.Lock()
		ownedNative.byTag[c.Tag].addresses = append(ownedNative.byTag[c.Tag].addresses, row)
		ownedNative.Unlock()
	}
	return nil
}

func nativeAddRoutes(c Config) error {
	for _, spec := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		prefix := netip.MustParsePrefix(spec)
		var row windows.MibIpForwardRow2
		initializeRoute.Call(uintptr(unsafe.Pointer(&row)))
		row.InterfaceIndex = uint32(c.Index)
		row.DestinationPrefix.Prefix = ipSockaddr(prefix.Addr())
		row.DestinationPrefix.PrefixLength = uint8(prefix.Bits())
		if prefix.Addr().Is4() {
			row.NextHop = ipSockaddr(netip.IPv4Unspecified())
		} else {
			row.NextHop = ipSockaddr(netip.IPv6Unspecified())
		}
		row.Metric = 1
		if err := callIPHelper(createRoute, unsafe.Pointer(&row)); err != nil {
			return fmt.Errorf("create route %s: %w", spec, err)
		}
		ownedNative.Lock()
		ownedNative.byTag[c.Tag].routes = append(ownedNative.byTag[c.Tag].routes, row)
		ownedNative.Unlock()
	}
	return nil
}

func nativeCleanup(c Config) error {
	ownedNative.Lock()
	resources := ownedNative.byTag[c.Tag]
	ownedNative.Unlock()
	if resources == nil {
		return nil
	}
	adapter := windows.MibIfRow2{InterfaceIndex: resources.index}
	if err := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &adapter); err != nil {
		return fmt.Errorf("cannot verify tunnel adapter before cleanup: %w", err)
	}
	if adapter.InterfaceGuid != resources.adapter {
		return fmt.Errorf("tunnel adapter identity changed before cleanup")
	}
	var failed error
	for i := len(resources.routes) - 1; i >= 0; i-- {
		row := resources.routes[i]
		if err := callIPHelper(deleteRoute, unsafe.Pointer(&row)); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			failed = errors.Join(failed, err)
		}
	}
	for i := len(resources.addresses) - 1; i >= 0; i-- {
		row := resources.addresses[i]
		if err := callIPHelper(deleteAddress, unsafe.Pointer(&row)); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			failed = errors.Join(failed, err)
		}
	}
	if failed == nil {
		ownedNative.Lock()
		delete(ownedNative.byTag, c.Tag)
		ownedNative.Unlock()
	}
	return failed
}
