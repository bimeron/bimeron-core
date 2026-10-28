//go:build windows

package killswitch

import (
	"errors"
	"net/netip"
	"syscall"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

const nativeProtectionName = "Bimeron IKEv2 protection"

// NativePending prevents a packet session from replacing a crashed native
// session's policy. Recovery must be explicit, under the shared VPN lock.
func NativePending() (bool, error) {
	s, err := open()
	if err != nil {
		return false, err
	}
	defer s.Close()
	rules, err := owned(s)
	for _, r := range rules {
		if r.Name == nativeProtectionName {
			return true, err
		}
	}
	return false, err
}

// Retain closes the management handle without deleting persistent filters.
func (g *Guard) Retain() error { return g.s.Close() }

func ArmIKEv2(index uint32, luid uint64, endpoint netip.Addr) (*Guard, error) {
	if index == 0 || luid == 0 || !endpoint.IsValid() || endpoint.IsUnspecified() || endpoint.IsMulticast() || endpoint.IsLoopback() || endpoint.Zone() != "" {
		return nil, errors.New("invalid native protection interface or endpoint")
	}
	s, err := open()
	if err != nil {
		return nil, err
	}
	var guard *Guard
	err = s.Transaction(func() error { var e error; guard, e = armIKEv2(s, index, luid, endpoint); return e })
	if err != nil {
		s.Close()
		return nil, err
	}
	return guard, nil
}

func armIKEv2(s api, index uint32, luid uint64, endpoint netip.Addr) (*Guard, error) {
	prior, err := owned(s)
	if err != nil {
		return nil, err
	}
	if len(prior) != 0 {
		return nil, errors.New("existing protection requires recovery")
	}
	if err = s.AddProvider(&wf.Provider{ID: provider, Name: "Bimeron", Persistent: true}); err != nil && !errors.Is(err, syscall.Errno(windows.FWP_E_ALREADY_EXISTS)) {
		return nil, err
	}
	if err = s.AddSublayer(&wf.Sublayer{ID: sublayer, Provider: provider, Name: "Bimeron kill switch", Persistent: true, Weight: 0xfffe}); err != nil && !errors.Is(err, syscall.Errno(windows.FWP_E_ALREADY_EXISTS)) {
		return nil, err
	}
	g := &Guard{s: s}
	match := func(field wf.FieldID, value any) *wf.Match {
		return &wf.Match{Field: field, Op: wf.MatchTypeEqual, Value: value}
	}
	add := func(layer wf.LayerID, weight uint64, action wf.Action, conditions ...*wf.Match) error {
		id, e := windows.GenerateGUID()
		if e != nil {
			return e
		}
		r := &wf.Rule{ID: wf.RuleID(id), Provider: provider, Sublayer: sublayer, Layer: layer, Name: nativeProtectionName, Weight: weight, Action: action, Persistent: true, Conditions: conditions}
		if e = s.AddRule(r); e != nil {
			return e
		}
		g.ids = append(g.ids, r.ID)
		return nil
	}
	for _, family := range []struct {
		v6     bool
		layers []wf.LayerID
	}{
		{false, []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthRecvAcceptV4, wf.LayerOutboundTransportV4, wf.LayerInboundTransportV4}},
		{true, []wf.LayerID{wf.LayerALEAuthConnectV6, wf.LayerALEAuthRecvAcceptV6, wf.LayerOutboundTransportV6, wf.LayerInboundTransportV6}},
	} {
		for _, layer := range family.layers {
			transport := layer == wf.LayerOutboundTransportV4 || layer == wf.LayerOutboundTransportV6 || layer == wf.LayerInboundTransportV4 || layer == wf.LayerInboundTransportV6
			vpn := []*wf.Match{match(wf.FieldIPLocalInterface, luid)}
			if transport {
				vpn = append(vpn, match(wf.FieldInterfaceIndex, index))
			}
			if err = add(layer, 1000, wf.ActionPermit, vpn...); err != nil {
				return nil, err
			}
			loop := netip.MustParsePrefix("127.0.0.0/8")
			if family.v6 {
				loop = netip.MustParsePrefix("::1/128")
			}
			if err = add(layer, 900, wf.ActionPermit, match(wf.FieldIPRemoteAddress, loop)); err != nil {
				return nil, err
			}
			if endpoint.Is6() == family.v6 {
				// Native RAS authorizes its kernel IP-in-IP carrier before IPsec
				// encapsulation. This is not a general application exemption.
				for _, protocol := range []uint8{4, 41} {
					conditions := []*wf.Match{match(wf.FieldIPProtocol, protocol), match(wf.FieldIPRemoteAddress, endpoint)}
					if !transport {
						conditions = append(conditions, match(wf.FieldALEAppID, "System"))
					}
					if err = add(layer, 800, wf.ActionPermit, conditions...); err != nil {
						return nil, err
					}
				}
				for _, port := range []uint16{500, 4500} {
					if err = add(layer, 800, wf.ActionPermit, match(wf.FieldIPProtocol, uint8(17)), match(wf.FieldIPLocalPort, port), match(wf.FieldIPRemotePort, port), match(wf.FieldIPRemoteAddress, endpoint)); err != nil {
						return nil, err
					}
				}
				if err = add(layer, 800, wf.ActionPermit, match(wf.FieldIPProtocol, uint8(50)), match(wf.FieldIPRemoteAddress, endpoint)); err != nil {
					return nil, err
				}
			}
			local, remote := uint16(68), uint16(67)
			if family.v6 {
				local, remote = 546, 547
			}
			if err = add(layer, 700, wf.ActionPermit, match(wf.FieldIPProtocol, uint8(17)), match(wf.FieldIPLocalPort, local), match(wf.FieldIPRemotePort, remote)); err != nil {
				return nil, err
			}
			if family.v6 {
				for _, prefix := range []string{"fe80::/10", "ff02::/16"} {
					for _, typ := range []uint16{133, 134, 135, 136} {
						// WFP represents ICMP type/code as local/remote port fields.
						if err = add(layer, 700, wf.ActionPermit, match(wf.FieldIPProtocol, uint8(58)), match(wf.FieldIPLocalPort, typ), match(wf.FieldIPRemotePort, uint16(0)), match(wf.FieldIPRemoteAddress, netip.MustParsePrefix(prefix))); err != nil {
							return nil, err
						}
					}
				}
			}
			if err = add(layer, 1, wf.ActionBlock); err != nil {
				return nil, err
			}
		}
	}
	return g, nil
}
