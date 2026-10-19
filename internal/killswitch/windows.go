//go:build windows

package killswitch

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
	"bimeron/internal/routing"
)

var provider = wf.ProviderID(windows.GUID{Data1: 0x9e7f8658, Data2: 0x5303, Data3: 0x43dd, Data4: [8]byte{0xa2, 0x80, 0x85, 0x96, 0xf9, 0x07, 0x0b, 0x31}})
var sublayer = wf.SublayerID(windows.GUID{Data1: 0xb1379d15, Data2: 0x3743, Data3: 0x45d0, Data4: [8]byte{0x9f, 0x51, 0xf1, 0x8c, 0x21, 0xa9, 0x42, 0x97}})

type api interface {
	Transaction(func() error) error
	AddProvider(*wf.Provider) error
	AddSublayer(*wf.Sublayer) error
	AddRule(*wf.Rule) error
	Rules() ([]*wf.Rule, error)
	DeleteRule(wf.RuleID) error
	DeleteSublayer(wf.SublayerID) error
	DeleteProvider(wf.ProviderID) error
	Close() error
}

func open() (api, error) { return wf.New(&wf.Options{Name: "Bimeron kill switch", Dynamic: false}) }

type Guard struct {
	s   api
	ids []wf.RuleID
}

func Pending() (bool, error) {
	s, err := open()
	if err != nil {
		return false, err
	}
	defer s.Close()
	r, err := owned(s)
	return len(r) > 0, err
}
func owned(s api) ([]*wf.Rule, error) {
	rules, err := s.Rules()
	if err != nil {
		return nil, err
	}
	var result []*wf.Rule
	for _, r := range rules {
		if r.Provider == provider && r.Sublayer == sublayer {
			result = append(result, r)
		}
	}
	return result, nil
}
func interfaceLUID(index int) (uint64, error) {
	var luid uint64
	p := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceIndexToLuid")
	r, _, _ := p.Call(uintptr(index), uintptr(unsafe.Pointer(&luid)))
	if r != 0 {
		return 0, syscall.Errno(r)
	}
	return luid, nil
}
func Arm(index int, p *routing.Policy, disableIPv6 bool) (*Guard, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	app, err := wf.AppID(exe)
	if err != nil {
		return nil, err
	}
	luid, err := interfaceLUID(index)
	if err != nil {
		return nil, err
	}
	plan, err := Plan(p, disableIPv6)
	if err != nil {
		return nil, err
	}
	s, err := open()
	if err != nil {
		return nil, err
	}
	var g *Guard
	err = s.Transaction(func() error { var e error; g, e = arm(s, luid, app, plan); return e })
	if err != nil {
		s.Close()
		return nil, err
	}
	return g, nil
}
func arm(s api, luid uint64, app string, plan []EgressRule) (*Guard, error) {
	prior, err := owned(s)
	if err != nil {
		return nil, err
	}
	// Restart never removes the crashed process's block first. New permits are
	// installed before deny rules; old rules are removed only after replacement.
	if err = s.AddProvider(&wf.Provider{ID: provider, Name: "Bimeron", Persistent: true}); err != nil && !errors.Is(err, syscall.Errno(windows.FWP_E_ALREADY_EXISTS)) {
		return nil, err
	}
	if err = s.AddSublayer(&wf.Sublayer{ID: sublayer, Provider: provider, Name: "Bimeron kill switch", Persistent: true, Weight: 0xfffe}); err != nil && !errors.Is(err, syscall.Errno(windows.FWP_E_ALREADY_EXISTS)) {
		return nil, err
	}
	g := &Guard{s: s}
	add := func(layer wf.LayerID, weight uint64, allow bool, conditions ...*wf.Match) error {
		id, err := windows.GenerateGUID()
		if err != nil {
			return err
		}
		action := wf.ActionBlock
		if allow {
			action = wf.ActionPermit
		}
		r := &wf.Rule{ID: wf.RuleID(id), Provider: provider, Sublayer: sublayer, Layer: layer, Name: "Bimeron protection", Weight: weight, Action: action, Persistent: true, Conditions: conditions}
		if err = s.AddRule(r); err != nil {
			return err
		}
		g.ids = append(g.ids, r.ID)
		return nil
	}
	match := func(f wf.FieldID, v any) *wf.Match { return &wf.Match{Field: f, Op: wf.MatchTypeEqual, Value: v} }
	var installErr error
	for _, layer := range []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6, wf.LayerALEAuthRecvAcceptV4, wf.LayerALEAuthRecvAcceptV6} {
		if err = add(layer, ^uint64(0), true, match(wf.FieldALEAppID, app)); err != nil {
			installErr = err
			break
		}
		if err = add(layer, ^uint64(0)-1, true, match(wf.FieldIPLocalInterface, luid)); err != nil {
			installErr = err
			break
		}
		ipv6 := layer == wf.LayerALEAuthConnectV6 || layer == wf.LayerALEAuthRecvAcceptV6
		loop := netip.MustParsePrefix("127.0.0.0/8")
		if ipv6 {
			loop = netip.MustParsePrefix("::1/128")
		}
		if err = add(layer, ^uint64(0)-2, true, match(wf.FieldIPRemoteAddress, loop)); err != nil {
			installErr = err
			break
		}
		// DHCP is required to recover after a network change. Permit only the
		// client/server port pair, never general DNS or HTTPS by other apps.
		local, remote := uint16(68), uint16(67)
		if ipv6 {
			local, remote = 546, 547
		}
		if err = add(layer, ^uint64(0)-3, true, match(wf.FieldIPProtocol, uint8(17)), match(wf.FieldIPLocalPort, local), match(wf.FieldIPRemotePort, remote)); err != nil {
			installErr = err
			break
		}
		if ipv6 {
			for _, prefix := range []string{"fe80::/10", "ff02::/16"} {
				if err = add(layer, ^uint64(0)-4, true, match(wf.FieldIPProtocol, uint8(58)), match(wf.FieldIPRemoteAddress, netip.MustParsePrefix(prefix))); err != nil {
					installErr = err
					break
				}
			}
		}
	}
	// Prefix rules retain first-match order. Allows first, blocks afterwards:
	// setup cannot accidentally cut off its own recovery transport mid-install.
	for _, allow := range []bool{true, false} {
		for _, rule := range plan {
			if installErr != nil {
				break
			}
			if rule.Allow != allow {
				continue
			}
			layer := wf.LayerALEAuthConnectV4
			if rule.Prefix.Addr().Is6() {
				layer = wf.LayerALEAuthConnectV6
			}
			incoming := wf.LayerALEAuthRecvAcceptV4
			if rule.Prefix.Addr().Is6() {
				incoming = wf.LayerALEAuthRecvAcceptV6
			}
			for _, l := range []wf.LayerID{layer, incoming} {
				if err = add(l, rule.Weight, allow, match(wf.FieldIPRemoteAddress, rule.Prefix)); err != nil {
					installErr = err
					break
				}
			}
		}
	}
	if installErr != nil {
		// Remove only this failed attempt, preserving previous persistent filters.
		for _, id := range g.ids {
			_ = s.DeleteRule(id)
		}
		return nil, fmt.Errorf("kill switch installation failed: %w", installErr)
	}
	for _, r := range prior {
		if err = s.DeleteRule(r.ID); err != nil {
			// Keep the new deny rules installed; recover is required on cleanup error.
			return nil, fmt.Errorf("kill switch replacement failed: %w", err)
		}
	}
	return g, nil
}
func (g *Guard) Close() error {
	if g == nil {
		return nil
	}
	err := g.s.Transaction(func() error { return remove(g.s) })
	closeErr := g.s.Close()
	return errors.Join(err, closeErr)
}
func remove(s api) error {
	rules, err := owned(s)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if err = s.DeleteRule(r.ID); err != nil {
			return err
		}
	}
	if err = s.DeleteSublayer(sublayer); err != nil && !errors.Is(err, syscall.Errno(windows.FWP_E_SUBLAYER_NOT_FOUND)) {
		return err
	}
	if err = s.DeleteProvider(provider); err != nil && !errors.Is(err, syscall.Errno(windows.FWP_E_PROVIDER_NOT_FOUND)) {
		return err
	}
	return nil
}

// Recover removes only Bimeron-owned WFP objects. The caller must hold the VPN lock.
func Recover() error {
	s, err := open()
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Transaction(func() error { return remove(s) })
}
