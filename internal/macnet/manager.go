package macnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Runner func(context.Context, string, string, ...string) ([]byte, error)
type Manager struct {
	Dir    string
	Run    Runner
	Index  func(string) (int, error)
	BootID func() (string, error)
}
type DNSBackup struct {
	ID       string
	Original []string
}
type State struct {
	Version          int
	BootID           string
	Name             string
	Index            int
	Routes           bool
	DNS              []DNSBackup
	BootstrapDevice  string
	BootstrapGateway string
	BootstrapDNS     []string
	Bypass           *BypassRoute `json:",omitempty"`
}
type BypassRoute struct {
	Device, Gateway string
	Index           int
}
type service struct {
	ID, Name string
	Disabled bool
}

func (m *Manager) command(ctx context.Context, name string, args ...string) ([]byte, error) {
	return m.Run(ctx, name, "", args...)
}
func (m *Manager) Load() (*State, error) {
	b, err := os.ReadFile(filepath.Join(m.Dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if json.Unmarshal(b, &s) != nil || s.Version != 1 || !validTunnel(s.Name) || s.Index <= 0 {
		return nil, fmt.Errorf("invalid macOS recovery journal")
	}
	for _, dns := range s.DNS {
		if !validServiceID(dns.ID) {
			return nil, fmt.Errorf("invalid DNS service ID in journal")
		}
		for _, server := range dns.Original {
			if _, err := netip.ParseAddr(server); err != nil {
				return nil, fmt.Errorf("invalid original DNS in journal")
			}
		}
	}
	if s.Bypass != nil {
		device, gateway, err := ParseDefaultRoute("interface: " + s.Bypass.Device + "\ngateway: " + s.Bypass.Gateway)
		if err != nil || device != s.Bypass.Device || gateway != s.Bypass.Gateway || s.Bypass.Index <= 0 {
			return nil, fmt.Errorf("invalid macOS bypass route in journal")
		}
	}
	return &s, nil
}

// Bound sockets require an interface-scoped default route once utun /1 routes
// become the global primary route. Existing scoped defaults are never owned.
func (m *Manager) EnsureBypass(ctx context.Context, device, gateway string) error {
	s, err := m.Load()
	if err != nil || s == nil {
		return err
	}
	return m.ensureBypass(ctx, s, device, gateway)
}
func (m *Manager) clearBypass(ctx context.Context, s *State) error {
	if s.Bypass == nil {
		return nil
	}
	b := s.Bypass
	rows, err := m.routes(ctx)
	if err != nil {
		return err
	}
	index, _ := m.Index(b.Device)
	for _, r := range rows {
		if r.Prefix == "0.0.0.0/0" && r.Scoped && r.Device == b.Device && r.Gateway == b.Gateway && index == b.Index {
			if _, err := m.command(ctx, "route", "-q", "-n", "delete", "-inet", "default", b.Gateway, "-ifscope", b.Device); err != nil {
				return err
			}
		}
	}
	s.Bypass = nil
	return m.save(s)
}
func (m *Manager) ensureBypass(ctx context.Context, s *State, device, gateway string) error {
	index, err := m.Index(device)
	if err != nil {
		return err
	}
	if s.Bypass != nil && (s.Bypass.Device != device || s.Bypass.Gateway != gateway || s.Bypass.Index != index) {
		if err := m.clearBypass(ctx, s); err != nil {
			return err
		}
	}
	rows, err := m.routes(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.Prefix == "0.0.0.0/0" && r.Scoped && r.Device == device {
			if r.Gateway != gateway {
				return fmt.Errorf("macos_scoped_route_conflict")
			}
			return nil
		}
	}
	s.Bypass = &BypassRoute{Device: device, Gateway: gateway, Index: index}
	if err := m.save(s); err != nil {
		return err
	}
	_, err = m.command(ctx, "route", "-q", "-n", "add", "-inet", "default", gateway, "-ifscope", device)
	return err
}
func (m *Manager) save(s *State) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(m.Dir, "state.tmp"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(filepath.Join(m.Dir, "state.tmp"), filepath.Join(m.Dir, "state.json"))
}
func (m *Manager) routes(ctx context.Context) ([]Route, error) {
	var result []Route
	for _, family := range []string{"inet", "inet6"} {
		b, err := m.command(ctx, "netstat", "-rn", "-f", family)
		if err != nil {
			return nil, err
		}
		rows, err := ParseRoutes(string(b))
		if err != nil {
			return nil, err
		}
		result = append(result, rows...)
	}
	return result, nil
}
func (m *Manager) Preflight(ctx context.Context) error {
	rows, err := m.routes(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		for _, prefix := range CaptureRoutes() {
			if r.Prefix == prefix {
				return fmt.Errorf("macos_capture_route_already_in_use")
			}
		}
	}
	services, err := m.services(ctx)
	if err != nil {
		return err
	}
	for _, service := range services {
		dns, err := m.dns(ctx, service.Name)
		if err != nil {
			return err
		}
		for _, server := range dns {
			if server == TunnelDNS {
				return fmt.Errorf("macos_tunnel_dns_already_in_use_run_recover")
			}
		}
	}
	return nil
}
func (m *Manager) Default(ctx context.Context) (string, string, error) {
	b, err := m.command(ctx, "route", "-n", "get", "-inet", "default")
	if err != nil {
		return "", "", ErrNetworkUnavailable
	}
	return ParseDefaultRoute(string(b))
}
func (m *Manager) BootstrapDNS(ctx context.Context, device string) []string {
	b, err := m.command(ctx, "scutil", "--dns")
	if err == nil {
		if dns := ParseBootstrapDNS(string(b), device); len(dns) > 0 {
			return dns
		}
	}
	if s, err := m.Load(); err == nil && s != nil && s.BootstrapDevice == device {
		_, gateway, err := m.Default(ctx)
		if err == nil && gateway == s.BootstrapGateway {
			return append([]string(nil), s.BootstrapDNS...)
		}
	}
	return nil
}
func (m *Manager) services(ctx context.Context) ([]service, error) {
	enabled, err := m.command(ctx, "networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	lines := strings.Split(strings.TrimSpace(string(enabled)), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("cannot list network services")
	}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line != "" {
			names[strings.TrimPrefix(line, "*")] = strings.HasPrefix(line, "*")
		}
	}
	out, err := m.Run(ctx, "scutil", "list Setup:/Network/Service/[^/]+$\nquit\n")
	if err != nil {
		return nil, err
	}
	var result []service
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		_, key, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		id := strings.TrimPrefix(strings.TrimSpace(key), "Setup:/Network/Service/")
		if !validServiceID(id) || seen[id] {
			continue
		}
		seen[id] = true
		data, err := m.Run(ctx, "scutil", "show Setup:/Network/Service/"+id+"\nquit\n")
		if err != nil {
			return nil, err
		}
		name := dictionaryValue(string(data), "UserDefinedName")
		disabled, exists := names[name]
		if !exists {
			// networksetup can expose the interface name (for example iPhone USB)
			// instead of the service dictionary's name (iPhone).
			data, err := m.Run(ctx, "scutil", "show Setup:/Network/Service/"+id+"/Interface\nquit\n")
			if err != nil {
				return nil, err
			}
			name = dictionaryValue(string(data), "UserDefinedName")
			disabled, exists = names[name]
		}
		if exists {
			for _, existing := range result {
				if existing.Name == name {
					return nil, fmt.Errorf("ambiguous macOS network service ID")
				}
			}
			result = append(result, service{ID: id, Name: name, Disabled: disabled})
		}
	}
	if len(result) != len(names) {
		return nil, fmt.Errorf("cannot match macOS network service IDs")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}
func (m *Manager) dns(ctx context.Context, name string) ([]string, error) {
	b, err := m.command(ctx, "networksetup", "-getdnsservers", name)
	if err != nil {
		return nil, err
	}
	return ParseExplicitDNS(string(b))
}
func (m *Manager) setDNS(ctx context.Context, name string, dns []string) error {
	args := []string{"-setdnsservers", name}
	if len(dns) == 0 {
		args = append(args, "Empty")
	} else {
		args = append(args, dns...)
	}
	out, err := m.command(ctx, "networksetup", args...)
	if err != nil || strings.TrimSpace(string(out)) != "" {
		return fmt.Errorf("cannot set network service DNS")
	}
	actual, err := m.dns(ctx, name)
	if err != nil || !equal(actual, dns) {
		return fmt.Errorf("network service DNS verification failed")
	}
	return nil
}

// RefreshDNS clears stale resolver state after the physical network returns.
func (m *Manager) RefreshDNS(ctx context.Context) error {
	if _, err := m.command(ctx, "killall", "-HUP", "mDNSResponder"); err != nil {
		return fmt.Errorf("cannot refresh macOS DNS state")
	}
	return nil
}
func equal(a, b []string) bool { return strings.Join(a, "\n") == strings.Join(b, "\n") }

// EnsureDNS saves originals before every mutation, including newly added services.
// Services are tracked by stable UUIDs, so renaming one cannot lose its backup.
func (m *Manager) EnsureDNS(ctx context.Context) error {
	s, err := m.Load()
	if err != nil || s == nil {
		return err
	}
	services, err := m.services(ctx)
	if err != nil {
		return err
	}
	for _, service := range services {
		found := false
		for _, b := range s.DNS {
			if b.ID == service.ID {
				found = true
				break
			}
		}
		current, err := m.dns(ctx, service.Name)
		if err != nil {
			return err
		}
		if found {
			if !equal(current, []string{TunnelDNS}) {
				return ErrDNSConflict
			}
			continue
		}
		if service.Disabled {
			continue
		}
		s.DNS = append(s.DNS, DNSBackup{ID: service.ID, Original: current})
		if err := m.save(s); err != nil {
			return err
		}
		if err := m.setDNS(ctx, service.Name, []string{TunnelDNS}); err != nil {
			return err
		}
	}
	effective, err := m.command(ctx, "scutil", "--dns")
	if err != nil {
		return err
	}
	servers := ParseDefaultDNS(string(effective))
	if len(servers) > 0 && !equal(servers, []string{TunnelDNS}) {
		return ErrDNSConflict
	}
	return nil
}
func (m *Manager) Configure(ctx context.Context, name string, mtu int) (err error) {
	if !validTunnel(name) {
		return fmt.Errorf("invalid utun name")
	}
	index, err := m.Index(name)
	if err != nil {
		return err
	}
	if index <= 0 {
		return fmt.Errorf("invalid utun interface index")
	}
	device, gateway, err := m.Default(ctx)
	if err != nil {
		return err
	}
	s := &State{Version: 1, Name: name, Index: index, BootstrapDevice: device, BootstrapGateway: gateway, BootstrapDNS: m.BootstrapDNS(ctx, device)}
	if m.BootID != nil {
		s.BootID, err = m.BootID()
		if err != nil {
			return err
		}
	}
	if err = m.save(s); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			cleanCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			err = errors.Join(err, m.Recover(cleanCtx, false))
		}
	}()
	if err = m.ensureBypass(ctx, s, device, gateway); err != nil {
		return fmt.Errorf("macos_bypass_route_setup_failed: %w", err)
	}
	for _, args := range [][]string{
		{name, "inet", "198.18.0.1", "198.18.0.1", "netmask", "255.255.255.255", "alias"},
		{name, "inet6", "fdfe:524c::1", "prefixlen", "128", "alias"},
		{name, "mtu", strconv.Itoa(mtu), "up"},
	} {
		if _, err = m.command(ctx, "ifconfig", args...); err != nil {
			return fmt.Errorf("macos_adapter_setup_failed")
		}
	}
	// Verify resolver ownership before capture routes can disrupt another
	// provider's upstream connection.
	if err = m.EnsureDNS(ctx); err != nil {
		return err
	}
	s, err = m.Load()
	if err != nil {
		return err
	}
	if s == nil {
		return fmt.Errorf("macOS recovery state disappeared")
	}
	s.Routes = true
	if err = m.save(s); err != nil {
		return err
	}
	for _, prefix := range CaptureRoutes() {
		p := netip.MustParsePrefix(prefix)
		family := "-inet"
		if p.Addr().Is6() {
			family = "-inet6"
		}
		if _, err = m.command(ctx, "route", "-q", "-n", "add", family, "-net", prefix, "-interface", name); err != nil {
			return fmt.Errorf("macos_route_setup_failed")
		}
	}
	return nil
}
func (m *Manager) Recover(ctx context.Context, keepCurrentDNS bool) error {
	s, err := m.Load()
	if err != nil || s == nil {
		return err
	}
	var failures []error
	if len(s.DNS) > 0 {
		services, e := m.services(ctx)
		if e != nil {
			failures = append(failures, e)
		} else {
			var remaining []DNSBackup
			for _, backup := range s.DNS {
				name := ""
				for _, service := range services {
					if service.ID == backup.ID {
						name = service.Name
						break
					}
				}
				if name == "" {
					continue
				}
				current, e := m.dns(ctx, name)
				if e == nil && equal(current, backup.Original) {
				} else if e == nil && equal(current, []string{TunnelDNS}) {
					e = m.setDNS(ctx, name, backup.Original)
				} else if e == nil {
					if keepCurrentDNS {
						continue
					}
					e = ErrDNSConflict
				}
				if e != nil {
					remaining = append(remaining, backup)
					failures = append(failures, e)
				}
			}
			s.DNS = remaining
		}
	}
	sameBoot := true
	if (s.Routes || s.Bypass != nil) && m.BootID != nil {
		boot, e := m.BootID()
		if e != nil {
			failures = append(failures, e)
			sameBoot = false
		} else if boot != s.BootID {
			s.Routes = false
			s.Bypass = nil
			sameBoot = false
		}
	}
	if sameBoot {
		if err := m.clearBypass(ctx, s); err != nil {
			failures = append(failures, err)
		}
	}
	if s.Routes && sameBoot {
		rows, e := m.routes(ctx)
		if e != nil {
			failures = append(failures, e)
		} else {
			currentIndex, _ := m.Index(s.Name)
			routeFailed := false
			for _, r := range rows {
				owned := false
				for _, prefix := range CaptureRoutes() {
					if r.Prefix == prefix {
						owned = true
					}
				}
				if !owned || r.Device != s.Name || (r.Index != s.Index && currentIndex != s.Index) {
					continue
				}
				p := netip.MustParsePrefix(r.Prefix)
				family := "-inet"
				if p.Addr().Is6() {
					family = "-inet6"
				}
				if _, e := m.command(ctx, "route", "-q", "-n", "delete", family, "-net", r.Prefix, "-interface", s.Name); e != nil {
					failures = append(failures, e)
					routeFailed = true
				}
			}
			if !routeFailed {
				s.Routes = false
			}
		}
	}
	if e := m.save(s); e != nil {
		failures = append(failures, e)
	}
	if len(failures) == 0 {
		return os.Remove(filepath.Join(m.Dir, "state.json"))
	}
	return errors.Join(failures...)
}
