package macnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

const wifiID = "11111111-1111-1111-1111-111111111111"
const ethernetID = "22222222-2222-2222-2222-222222222222"

func TestExistingScopedDefaultIsPreserved(t *testing.T) {
	m, f := testMacManager(t)
	f.routes = []Route{{Prefix: "0.0.0.0/0", Device: "en0", Gateway: "192.0.2.1", Scoped: true}}
	ctx := context.Background()
	if err := m.Configure(ctx, "utun3", 1420); err != nil {
		t.Fatal(err)
	}
	s, err := m.Load()
	if err != nil || s.Bypass != nil {
		t.Fatal("claimed existing route", s, err)
	}
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 1 || !f.routes[0].Scoped {
		t.Fatal("removed existing default", f.routes)
	}
}

func TestBypassMigratesAndPreservesForeignGateway(t *testing.T) {
	m, f := testMacManager(t)
	ctx := context.Background()
	if err := m.Configure(ctx, "utun3", 1420); err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureBypass(ctx, "en1", "192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	s, err := m.Load()
	if err != nil || s.Bypass == nil || s.Bypass.Device != "en1" {
		t.Fatal("route not migrated", s, err)
	}
	for i := range f.routes {
		if f.routes[i].Scoped {
			if f.routes[i].Device != "en1" {
				t.Fatal("old route leaked")
			}
			f.routes[i].Gateway = "192.0.2.3"
		}
	}
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 1 || f.routes[0].Gateway != "192.0.2.3" {
		t.Fatal("foreign route changed", f.routes)
	}
}

func TestBypassDeletionFailureRetainsRecoveryJournal(t *testing.T) {
	m, f := testMacManager(t)
	ctx := context.Background()
	if err := m.Configure(ctx, "utun3", 1420); err != nil {
		t.Fatal(err)
	}
	f.fail = "delete -inet default"
	if err := m.Recover(ctx, false); err == nil {
		t.Fatal("expected cleanup failure")
	}
	s, err := m.Load()
	if err != nil || s == nil || s.Bypass == nil {
		t.Fatal("lost recovery journal", s, err)
	}
	f.fail = ""
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 0 {
		t.Fatal("route leaked", f.routes)
	}
}

func TestServicesUsesInterfaceNameWhenServiceNameDiffers(t *testing.T) {
	m, fake := testMacManager(t)
	fake.names[wifiID] = "iPhone USB"
	m.Run = func(ctx context.Context, name, input string, args ...string) ([]byte, error) {
		if name == "scutil" && strings.HasPrefix(input, "show Setup:/Network/Service/"+wifiID) {
			value := "iPhone"
			if strings.Contains(input, "/Interface\n") {
				value = "iPhone USB"
			}
			return []byte("<dictionary> {\n UserDefinedName : " + value + "\n}\n"), nil
		}
		return fake.run(ctx, name, input, args...)
	}
	services, err := m.services(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 2 || services[0].ID != wifiID || services[0].Name != "iPhone USB" {
		t.Fatalf("incorrect service mapping: %+v", services)
	}
}

type fakeMac struct {
	names        map[string]string
	dns          map[string][]string
	routes       []Route
	calls        []string
	fail         string
	effectiveDNS string
	holdDNS      bool
}

func newFakeMac() *fakeMac {
	return &fakeMac{
		names:        map[string]string{wifiID: "Wi-Fi", ethernetID: "Ethernet"},
		dns:          map[string][]string{wifiID: nil, ethernetID: {"9.9.9.9", "2001:4860:4860::8888"}},
		effectiveDNS: "DNS configuration\nresolver #1\n nameserver[0] : 192.0.2.53\n if_index : 4 (en0)\n",
	}
}
func (f *fakeMac) run(_ context.Context, name, input string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, command)
	if f.fail != "" && strings.Contains(command, f.fail) {
		return nil, errors.New("injected failure")
	}
	if name == "netstat" {
		var b strings.Builder
		b.WriteString("Destination Gateway Flags Netif Expire\n")
		family := args[len(args)-1]
		if family == "inet6" {
			b.WriteString("Internet6:\n")
		}
		for _, r := range f.routes {
			p := netip.MustParsePrefix(r.Prefix)
			if (family == "inet") == p.Addr().Is4() {
				dst := r.Prefix
				if p.Bits() == p.Addr().BitLen() {
					dst = p.Addr().String()
				}
				gateway, flags := fmt.Sprintf("link#%d", r.Index), "UCS"
				if r.Scoped {
					gateway, flags, dst = r.Gateway, "UGScI", "default"
				}
				fmt.Fprintf(&b, "%s %s %s %s\n", dst, gateway, flags, r.Device)
			}
		}
		return []byte(b.String()), nil
	}
	if name == "route" {
		if len(args) > 1 && args[1] == "get" {
			return []byte("route to: default\ngateway: 192.0.2.1\ninterface: en0\n"), nil
		}
		if len(args) >= 8 && args[2] == "add" {
			r := Route{Prefix: args[5], Device: args[7], Index: 12}
			if args[6] == "-ifscope" {
				r.Prefix, r.Gateway, r.Scoped = "0.0.0.0/0", args[5], true
			}
			f.routes = append(f.routes, r)
		}
		if len(args) >= 8 && args[2] == "delete" {
			var remaining []Route
			for _, r := range f.routes {
				matches := r.Prefix == args[5] && r.Device == args[7]
				if args[6] == "-ifscope" {
					matches = r.Scoped && r.Gateway == args[5] && r.Device == args[7]
				}
				if !matches {
					remaining = append(remaining, r)
				}
			}
			f.routes = remaining
		}
		return nil, nil
	}
	if name == "scutil" {
		if strings.Contains(input, "list Setup:") {
			var b strings.Builder
			for id := range f.names {
				fmt.Fprintf(&b, " subKey [0] = Setup:/Network/Service/%s\n", id)
			}
			return []byte(b.String()), nil
		}
		if strings.Contains(input, "show Setup:") {
			for id, service := range f.names {
				if strings.Contains(input, id) {
					return []byte("<dictionary> {\n UserDefinedName : " + service + "\n}\n"), nil
				}
			}
		}
		return []byte(f.effectiveDNS), nil
	}
	if name == "networksetup" {
		if args[0] == "-listallnetworkservices" {
			var b strings.Builder
			b.WriteString("An asterisk (*) denotes disabled service.\n")
			for _, service := range f.names {
				b.WriteString(service + "\n")
			}
			return []byte(b.String()), nil
		}
		id := ""
		for key, service := range f.names {
			if service == args[1] {
				id = key
			}
		}
		if id == "" {
			return []byte("Error: unknown service"), nil
		}
		if args[0] == "-getdnsservers" {
			if len(f.dns[id]) == 0 {
				return []byte("There aren't any DNS Servers set on " + args[1] + ".\n"), nil
			}
			return []byte(strings.Join(f.dns[id], "\n") + "\n"), nil
		}
		if args[0] == "-setdnsservers" {
			if args[2] == "Empty" {
				f.dns[id] = nil
			} else {
				f.dns[id] = append([]string(nil), args[2:]...)
				if !f.holdDNS && args[2] == TunnelDNS {
					f.effectiveDNS = "DNS configuration\nresolver #1\n nameserver[0] : " + TunnelDNS + "\n"
				}
			}
			return nil, nil
		}
	}
	return nil, nil
}
func testMacManager(t *testing.T) (*Manager, *fakeMac) {
	t.Helper()
	fake := newFakeMac()
	return &Manager{Dir: t.TempDir(), Run: fake.run, Index: func(string) (int, error) { return 12, nil }}, fake
}

func TestRefreshDNSSignalsResponder(t *testing.T) {
	m, fake := testMacManager(t)
	if err := m.RefreshDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := fake.calls[len(fake.calls)-1]; got != "killall -HUP mDNSResponder" {
		t.Fatal(got)
	}
	fake.fail = "killall"
	if err := m.RefreshDNS(context.Background()); err == nil {
		t.Fatal("expected refresh failure")
	}
}

func TestConfigureRestoreDNSAndRoutes(t *testing.T) {
	m, f := testMacManager(t)
	ctx := context.Background()
	if err := m.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Configure(ctx, "utun3", 1420); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 6 || !equal(f.dns[wifiID], []string{TunnelDNS}) {
		t.Fatal("not configured", f.routes, f.dns)
	}
	if got := m.BootstrapDNS(ctx, "en0"); len(got) != 1 || got[0] != "192.0.2.53" {
		t.Fatal("lost bootstrap DNS", got)
	}
	f.names[wifiID] = "Renamed Wi-Fi"
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 0 || len(f.dns[wifiID]) != 0 || !equal(f.dns[ethernetID], []string{"9.9.9.9", "2001:4860:4860::8888"}) {
		t.Fatal("original settings not restored", f.routes, f.dns)
	}
	if s, err := m.Load(); err != nil || s != nil {
		t.Fatal("journal leaked", s, err)
	}
}
func TestPartialRouteFailureRollsBack(t *testing.T) {
	m, f := testMacManager(t)
	f.fail = "add -inet6 -net ::/1"
	if err := m.Configure(context.Background(), "utun3", 1420); err == nil {
		t.Fatal("expected failure")
	}
	if len(f.routes) != 0 || len(f.dns[wifiID]) != 0 {
		t.Fatal("partial setup leaked", f.routes, f.dns)
	}
}
func TestPartialDNSFailureRollsBackOtherServices(t *testing.T) {
	m, f := testMacManager(t)
	f.fail = "-setdnsservers Ethernet 198.18.0.2"
	if err := m.Configure(context.Background(), "utun3", 1420); err == nil {
		t.Fatal("expected DNS failure")
	}
	if len(f.routes) != 0 || len(f.dns[wifiID]) != 0 || f.dns[ethernetID][0] != "9.9.9.9" {
		t.Fatal("DNS rollback failed", f.routes, f.dns)
	}
}
func TestExternalDNSChangeIsPreserved(t *testing.T) {
	m, f := testMacManager(t)
	ctx := context.Background()
	if err := m.Configure(ctx, "utun3", 1420); err != nil {
		t.Fatal(err)
	}
	f.dns[wifiID] = []string{"8.8.8.8"}
	if err := m.EnsureDNS(ctx); !errors.Is(err, ErrDNSConflict) {
		t.Fatal("external update not detected", err)
	}
	if err := m.Recover(ctx, false); !errors.Is(err, ErrDNSConflict) {
		t.Fatal(err)
	}
	if f.dns[wifiID][0] != "8.8.8.8" || f.dns[ethernetID][0] != "9.9.9.9" {
		t.Fatal("overwrote externally updated DNS or failed other restoration", f.dns)
	}
	if err := m.Recover(ctx, true); err != nil {
		t.Fatal(err)
	}
}
func TestEffectiveDNSConflictFailsConfigure(t *testing.T) {
	m, f := testMacManager(t)
	f.holdDNS = true
	f.effectiveDNS = "DNS configuration\nresolver #1\n nameserver[0] : 127.0.2.2\n nameserver[1] : 127.0.2.3\n"
	if err := m.Configure(context.Background(), "utun3", 1420); !errors.Is(err, ErrDNSConflict) {
		t.Fatal("effective DNS conflict not detected", err)
	}
	if len(f.routes) != 0 || len(f.dns[wifiID]) != 0 || !equal(f.dns[ethernetID], []string{"9.9.9.9", "2001:4860:4860::8888"}) {
		t.Fatal("failed setup was not rolled back", f.routes, f.dns)
	}
	for _, call := range f.calls {
		if strings.Contains(call, " add -inet -net ") || strings.Contains(call, " add -inet6 -net ") {
			t.Fatal("capture route added before DNS ownership was verified", call)
		}
	}
}
func TestEffectiveDNSConflictStopsActiveSession(t *testing.T) {
	m, f := testMacManager(t)
	ctx := context.Background()
	if err := m.Configure(ctx, "utun3", 1420); err != nil {
		t.Fatal(err)
	}
	f.effectiveDNS = "DNS configuration\nresolver #1\n nameserver[0] : 127.0.2.2\n nameserver[1] : 127.0.2.3\n"
	if err := m.EnsureDNS(ctx); !errors.Is(err, ErrDNSConflict) {
		t.Fatal("runtime DNS conflict not detected", err)
	}
}
func TestRecoveryDoesNotDeleteForeignRoutes(t *testing.T) {
	m, f := testMacManager(t)
	ctx := context.Background()
	if err := m.Configure(ctx, "utun3", 1420); err != nil {
		t.Fatal(err)
	}
	f.routes = append(f.routes, Route{Prefix: "10.0.0.0/8", Device: "utun3", Index: 12}, Route{Prefix: "128.0.0.0/1", Device: "utun4", Index: 13})
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 2 {
		t.Fatal("deleted foreign routes", f.routes)
	}
}
func TestNewServiceDNSIsTracked(t *testing.T) {
	m, f := testMacManager(t)
	ctx := context.Background()
	if err := m.Configure(ctx, "utun3", 1420); err != nil {
		t.Fatal(err)
	}
	id := "33333333-3333-3333-3333-333333333333"
	f.names[id] = "USB LAN"
	f.dns[id] = []string{"8.8.4.4"}
	if err := m.EnsureDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if !equal(f.dns[id], []string{TunnelDNS}) {
		t.Fatal("new DNS not captured")
	}
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	if !equal(f.dns[id], []string{"8.8.4.4"}) {
		t.Fatal("new service original DNS lost")
	}
}
func TestCaptureRouteConflictDoesNotMutate(t *testing.T) {
	m, f := testMacManager(t)
	f.routes = []Route{{Prefix: "0.0.0.0/1", Device: "utun4", Index: 13}}
	if m.Preflight(context.Background()) == nil {
		t.Fatal("conflict accepted")
	}
	for _, call := range f.calls {
		if strings.Contains(call, " add ") || strings.Contains(call, "-setdnsservers") {
			t.Fatal("preflight mutated settings")
		}
	}
}

func TestRecoveryAfterRebootPreservesReusedInterfaceRoutes(t *testing.T) {
	m, f := testMacManager(t)
	boot := wifiID
	m.BootID = func() (string, error) { return boot, nil }
	ctx := context.Background()
	if err := m.Configure(ctx, "utun3", 1420); err != nil {
		t.Fatal(err)
	}
	boot = ethernetID
	// The old kernel routes disappeared; another VPN reused the name and index.
	f.routes = []Route{{Prefix: "0.0.0.0/1", Device: "utun3", Index: 12}}
	if err := m.Recover(ctx, false); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 1 || len(f.dns[wifiID]) != 0 {
		t.Fatal("reboot recovery changed foreign routes or lost DNS backup")
	}
}

func TestKeepCurrentDNSStillRestoresOtherServices(t *testing.T) {
	m, f := testMacManager(t)
	ctx := context.Background()
	if err := m.Configure(ctx, "utun3", 1420); err != nil {
		t.Fatal(err)
	}
	f.dns[wifiID] = []string{"8.8.8.8"}
	if err := m.Recover(ctx, true); err != nil {
		t.Fatal(err)
	}
	if !equal(f.dns[wifiID], []string{"8.8.8.8"}) || !equal(f.dns[ethernetID], []string{"9.9.9.9", "2001:4860:4860::8888"}) {
		t.Fatal("incorrect selective DNS restoration", f.dns)
	}
}

func TestInspectDiagnostics(t *testing.T) {
	m, fake := testMacManager(t)
	if err := m.Configure(context.Background(), "utun3", 1420); err != nil {
		t.Fatal(err)
	}
	fake.effectiveDNS = "DNS configuration\nresolver #1\n nameserver[0] : 192.0.2.53\n"
	diagnostics, err := m.InspectDiagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics.ActiveServices != 2 || diagnostics.TunnelDNSServices != 2 || diagnostics.CapturedIPv4Routes != 3 || diagnostics.CapturedIPv6Routes != 2 || diagnostics.EffectiveDNS != "other" || diagnostics.DNSConflict != "detected" {
		t.Fatalf("unexpected diagnostics: %+v", diagnostics)
	}
}

func TestInspectDiagnosticsDNSConflict(t *testing.T) {
	for _, test := range []struct {
		name, effectiveDNS, want string
		active                   bool
	}{
		{"conflicting provider", "DNS configuration\nresolver #1\n nameserver[0] : 127.0.2.2\n nameserver[1] : 127.0.2.3\n", "detected", true},
		{"tunnel", "DNS configuration\nresolver #1\n nameserver[0] : " + TunnelDNS + "\n", "not_detected", true},
		{"unavailable", "DNS configuration\n", "unavailable", true},
		{"inactive", "DNS configuration\nresolver #1\n nameserver[0] : 127.0.2.2\n", "not_applicable", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, fake := testMacManager(t)
			if test.active {
				if err := m.Configure(context.Background(), "utun3", 1420); err != nil {
					t.Fatal(err)
				}
			}
			fake.effectiveDNS = test.effectiveDNS
			diagnostics, err := m.InspectDiagnostics(context.Background())
			if err != nil || diagnostics.DNSConflict != test.want {
				t.Fatalf("got %+v, %v; want %s", diagnostics, err, test.want)
			}
		})
	}
}
