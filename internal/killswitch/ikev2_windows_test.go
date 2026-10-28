//go:build windows

package killswitch

import (
	"net/netip"
	"testing"

	"github.com/tailscale/wf"
)

func TestNativeProtectionHasNoAppEscapeAndCoversExistingTraffic(t *testing.T) {
	f := &fakeAPI{}
	endpoint := netip.MustParseAddr("192.0.2.56")
	if err := f.Transaction(func() error { _, err := armIKEv2(f, 25, 123, endpoint); return err }); err != nil {
		t.Fatal(err)
	}
	blocks := map[wf.LayerID]bool{}
	for _, r := range f.rules {
		if !r.Persistent || r.Provider != provider || r.Sublayer != sublayer || r.Name != nativeProtectionName {
			t.Fatal("unowned or nonpersistent rule")
		}
		if r.Action == wf.ActionBlock {
			blocks[r.Layer] = true
			continue
		}
		local, idx := false, false
		system, carrier, peer := false, false, false
		for _, c := range r.Conditions {
			if c.Field == wf.FieldALEAppID && c.Value != "System" {
				t.Fatal("application bypass would allow clear traffic")
			}
			if c.Field == wf.FieldALEAppID {
				system = true
			}
			if c.Field == wf.FieldIPProtocol {
				carrier = c.Value == uint8(4) || c.Value == uint8(41)
			}
			if c.Field == wf.FieldIPRemoteAddress && c.Value == endpoint {
				peer = true
			}
			if c.Field == wf.FieldIPLocalInterface {
				local = c.Value == uint64(123)
			}
			if c.Field == wf.FieldInterfaceIndex {
				idx = c.Value == uint32(25)
			}
		}
		if system && (!carrier || !peer) {
			t.Fatal("System exception is not constrained to the native peer/carrier")
		}
		transport := r.Layer == wf.LayerOutboundTransportV4 || r.Layer == wf.LayerOutboundTransportV6 || r.Layer == wf.LayerInboundTransportV4 || r.Layer == wf.LayerInboundTransportV6
		if local && transport && !idx {
			t.Fatal("VPN permit not bound to actual interface index")
		}
	}
	if len(blocks) != 8 {
		t.Fatal("missing ALE or per-packet transport blocks", blocks)
	}
	if err := (&Guard{s: f}).Close(); err != nil || len(f.rules) != 0 {
		t.Fatal("native filters not recovered", err)
	}
}

func TestNativeInstallationFailureIsAtomicAndRetainKeepsFilters(t *testing.T) {
	for _, fail := range []int{1, 10, 40, 60} {
		f := &fakeAPI{failAt: fail}
		err := f.Transaction(func() error { _, e := armIKEv2(f, 25, 123, netip.MustParseAddr("192.0.2.56")); return e })
		if err == nil || len(f.rules) != 0 {
			t.Fatal("partial native policy committed", fail, err)
		}
	}
	f := &fakeAPI{}
	g, err := armIKEv2(f, 25, 123, netip.MustParseAddr("192.0.2.56"))
	if err != nil {
		t.Fatal(err)
	}
	count := len(f.rules)
	if err = g.Retain(); err != nil || len(f.rules) != count {
		t.Fatal("retention removed filters", err)
	}
	if _, err = armIKEv2(f, 25, 123, netip.MustParseAddr("192.0.2.56")); err == nil {
		t.Fatal("retained policy silently replaced")
	}
}
