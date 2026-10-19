package linuxnet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"bimeron/internal/routing"
	"strconv"
	"strings"
	"time"
)

type Runner func(context.Context, string, string, ...string) ([]byte, error)
type Manager struct {
	Dir      string
	Resolver string
	Run      Runner
}
type State struct {
	Version      int
	Name         string
	Index        int
	Routing      bool
	Guard        bool
	DNSMethod    string
	DNSPath      string
	DNSOriginal  []byte
	DNSInstalled []byte
	DNSMode      uint32
}
type rule struct {
	Priority int             `json:"priority"`
	Table    json.RawMessage `json:"table"`
	Mark     json.RawMessage `json:"fwmark"`
	Protocol json.RawMessage `json:"protocol"`
	Input    string          `json:"iif"`
}
type route struct {
	Destination string          `json:"dst"`
	Type        string          `json:"type"`
	Device      string          `json:"dev"`
	Table       json.RawMessage `json:"table"`
	Protocol    json.RawMessage `json:"protocol"`
	Gateway     string          `json:"gateway"`
	Metric      int             `json:"metric"`
}

func scalar(b json.RawMessage) string { return strings.Trim(string(b), `"`) }
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
	if json.Unmarshal(b, &s) != nil || s.Version != 1 || !ValidName(s.Name) {
		return nil, fmt.Errorf("invalid Bimeron recovery journal")
	}
	return &s, nil
}

// KeepCurrentDNS is an explicit recovery choice when another network manager
// replaced resolv.conf. It never writes the external file.
func (m *Manager) KeepCurrentDNS() error {
	s, err := m.Load()
	if err != nil || s == nil {
		return err
	}
	if s.DNSMethod != "file" {
		return nil
	}
	if _, err := os.ReadFile(s.DNSPath); err != nil {
		return err
	}
	s.DNSMethod = ""
	return m.save(s)
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
func (m *Manager) rules(ctx context.Context, family string) ([]rule, error) {
	b, e := m.command(ctx, "ip", family, "-j", "rule", "show")
	var rows []rule
	if e == nil {
		e = json.Unmarshal(b, &rows)
	}
	return rows, e
}
func (m *Manager) routes(ctx context.Context, family string) ([]route, error) {
	b, e := m.command(ctx, "ip", family, "-j", "route", "show", "table", "all")
	var rows []route
	if e == nil {
		e = json.Unmarshal(b, &rows)
	}
	return rows, e
}

// Preflight refuses reserved priorities/tables and existing adapters before mutation.
func (m *Manager) Preflight(ctx context.Context, name string) error {
	if !ValidName(name) {
		return fmt.Errorf("Linux interface name must be at most 15 ASCII characters")
	}
	for _, family := range []string{"-4", "-6"} {
		rs, err := m.rules(ctx, family)
		if err != nil {
			return fmt.Errorf("cannot inspect routing rules")
		}
		for _, r := range rs {
			if r.Priority > 0 && r.Priority <= 10902 {
				return fmt.Errorf("conflicting policy routing; reserved priorities 10900-10902 must be free")
			}
		}
		routes, err := m.routes(ctx, family)
		if err != nil {
			return fmt.Errorf("cannot inspect routing tables")
		}
		for _, r := range routes {
			if scalar(r.Table) == Table {
				return fmt.Errorf("routing table 51892 is already in use")
			}
		}
	}
	b, err := m.command(ctx, "ip", "-j", "link", "show")
	if err != nil {
		return fmt.Errorf("cannot inspect interfaces")
	}
	var links []struct {
		Name string `json:"ifname"`
	}
	if json.Unmarshal(b, &links) != nil {
		return fmt.Errorf("cannot inspect interfaces")
	}
	for _, l := range links {
		if l.Name == name {
			return fmt.Errorf("tunnel name is already in use")
		}
	}
	return nil
}

func (m *Manager) guardPresent(ctx context.Context) (bool, error) {
	b, err := m.command(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		return false, fmt.Errorf("cannot inspect nftables; install nftables")
	}
	var data struct {
		Items []struct {
			Table *struct {
				Family  string `json:"family"`
				Name    string `json:"name"`
				Comment string `json:"comment"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal(b, &data) != nil {
		return false, fmt.Errorf("cannot inspect nftables")
	}
	for _, item := range data.Items {
		if item.Table != nil && item.Table.Family == "inet" && item.Table.Name == FirewallTable {
			// Some nft versions omit comments from list tables; inspect this table itself.
			full, err := m.command(ctx, "nft", "-j", "list", "table", "inet", FirewallTable)
			if err != nil {
				return false, err
			}
			var tableData struct {
				Items []struct {
					Table *struct {
						Comment string `json:"comment"`
					} `json:"table"`
				} `json:"nftables"`
			}
			if json.Unmarshal(full, &tableData) != nil {
				return false, fmt.Errorf("cannot inspect Bimeron firewall table")
			}
			for _, t := range tableData.Items {
				if t.Table != nil && t.Table.Comment == Owner {
					return true, nil
				}
			}
			// nftables 1.0.6 preserves table comments but omits them from JSON.
			text, textErr := m.command(ctx, "nft", "list", "table", "inet", FirewallTable)
			if textErr == nil && bytes.Contains(text, []byte(`comment "`+Owner+`"`)) {
				return true, nil
			}
			return false, fmt.Errorf("nftables table bimeron_core belongs to another owner")
		}
	}
	return false, nil
}

func (m *Manager) Configure(ctx context.Context, name string, mtu int, p *routing.Policy, disableIPv6, guard bool) (err error) {
	old, err := m.Load()
	if err != nil {
		return err
	}
	s := &State{Version: 1, Name: name, Guard: old != nil && old.Guard}
	linksJSON, e := m.command(ctx, "ip", "-j", "link", "show")
	if e != nil {
		return e
	}
	var links []struct {
		Name  string `json:"ifname"`
		Index int    `json:"ifindex"`
	}
	if json.Unmarshal(linksJSON, &links) != nil {
		return fmt.Errorf("cannot inspect TUN identity")
	}
	for _, l := range links {
		if l.Name == name {
			s.Index = l.Index
		}
	}
	if s.Index <= 0 {
		return fmt.Errorf("TUN interface not found")
	}
	if err = m.save(s); err != nil {
		return err
	}
	// Rollback also handles partial command failures; owned flags are saved first.
	defer func() {
		if err != nil {
			cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err = errors.Join(err, m.Recover(cleanCtx, false))
		}
	}()
	if _, err = m.command(ctx, "ip", "address", "add", "198.18.0.1/30", "dev", name); err != nil {
		return fmt.Errorf("cannot configure TUN IPv4")
	}
	if _, err = m.command(ctx, "ip", "-6", "address", "add", "fdfe:524c::1/126", "dev", name, "nodad"); err != nil {
		return fmt.Errorf("cannot configure TUN IPv6")
	}
	if _, err = m.command(ctx, "ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return fmt.Errorf("cannot enable TUN")
	}
	if guard {
		present, e := m.guardPresent(ctx)
		if e != nil {
			return e
		}
		script, e := Firewall(name, p, disableIPv6, present)
		if e != nil {
			return e
		}
		s.Guard = true
		if err = m.save(s); err != nil {
			return err
		}
		if _, e = m.Run(ctx, "nft", script, "-f", "-"); e != nil {
			return fmt.Errorf("cannot install nftables kill switch")
		}
	}
	s.Routing = true
	if err = m.save(s); err != nil {
		return err
	}
	for _, family := range []string{"-4", "-6"} {
		for _, prefix := range p.DirectPrefixes() {
			if (family == "-4") != prefix.Addr().Is4() {
				continue
			}
			if _, err = m.command(ctx, "ip", family, "route", "add", "throw", prefix.String(), "table", Table, "proto", Protocol); err != nil {
				return fmt.Errorf("cannot configure direct routes")
			}
		}
		for _, args := range [][]string{
			{family, "route", "add", "default", "dev", name, "table", Table, "proto", Protocol},
			{family, "rule", "add", "pref", BypassPriority, "fwmark", MarkText, "lookup", "main", "protocol", Protocol},
			{family, "rule", "add", "pref", TunnelPriority, "iif", "lo", "lookup", Table, "protocol", Protocol},
			{family, "rule", "add", "pref", TunnelInputPriority, "iif", name, "lookup", Table, "protocol", Protocol},
		} {
			if _, err = m.command(ctx, "ip", args...); err != nil {
				return fmt.Errorf("cannot configure tunnel policy routes")
			}
		}
	}
	return m.configureDNS(ctx, s)
}

func (m *Manager) configureDNS(ctx context.Context, s *State) error {
	// Use resolved only when applications actually use its stub/uplink resolv.conf.
	path, err := filepath.EvalSymlinks(m.Resolver)
	if err != nil {
		return fmt.Errorf("cannot locate resolv.conf")
	}
	original, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read resolv.conf")
	}
	resolved := strings.HasPrefix(path, "/run/systemd/resolve/") || bytes.Contains(original, []byte("nameserver 127.0.0.53")) || bytes.Contains(original, []byte("nameserver 127.0.0.54"))
	if resolved {
		s.DNSMethod = "resolved"
		if err = m.save(s); err != nil {
			return err
		}
		for _, args := range [][]string{{"dns", s.Name, "198.18.0.2"}, {"domain", s.Name, "~."}, {"default-route", s.Name, "yes"}, {"dnsovertls", s.Name, "no"}, {"dnssec", s.Name, "no"}} {
			if _, err = m.command(ctx, "resolvectl", args...); err != nil {
				return fmt.Errorf("cannot configure systemd-resolved")
			}
		}
		return nil
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("resolv.conf must be a regular file")
	}
	s.DNSMethod = "file"
	s.DNSPath = path
	s.DNSOriginal = original
	s.DNSMode = uint32(info.Mode().Perm())
	s.DNSInstalled = []byte("# Bimeron Core; restored on stop/recover\nnameserver 198.18.0.2\noptions timeout:2 attempts:2\n")
	if err = m.save(s); err != nil {
		return err
	}
	return os.WriteFile(path, s.DNSInstalled, info.Mode().Perm())
}

func ownedRule(r rule) bool {
	if scalar(r.Protocol) != Protocol {
		return false
	}
	if r.Priority == 10901 {
		return scalar(r.Table) == Table && r.Input == "lo"
	}
	if r.Priority == 10902 {
		return scalar(r.Table) == Table && ValidName(r.Input) && r.Input != "lo"
	}
	if r.Priority == 10900 {
		mark := scalar(r.Mark)
		return (mark == MarkText || mark == strconv.Itoa(Mark)) && (scalar(r.Table) == "main" || scalar(r.Table) == "254")
	}
	return false
}

func (m *Manager) Recover(ctx context.Context, preserveGuard bool) error {
	s, err := m.Load()
	if err != nil || s == nil {
		return err
	}
	var failures []error
	if s.DNSMethod == "file" {
		b, e := os.ReadFile(s.DNSPath)
		if e == nil && bytes.Equal(b, s.DNSOriginal) {
		} else if e == nil && bytes.Equal(b, s.DNSInstalled) {
			e = os.WriteFile(s.DNSPath, s.DNSOriginal, os.FileMode(s.DNSMode))
		} else if e == nil {
			e = fmt.Errorf("resolv.conf changed externally; refusing to overwrite; see Linux recovery documentation")
		}
		if e != nil {
			failures = append(failures, e)
		} else {
			s.DNSMethod = ""
		}
	} else if s.DNSMethod == "resolved" {
		// TUN is nonpersistent; a vanished interface has no resolved link settings.
		b, e := m.command(ctx, "ip", "-j", "link", "show")
		var links []struct {
			Name  string `json:"ifname"`
			Index int    `json:"ifindex"`
		}
		if e == nil {
			e = json.Unmarshal(b, &links)
		}
		found := false
		for _, l := range links {
			if l.Name == s.Name && l.Index == s.Index {
				found = true
			}
		}
		if e == nil && found {
			_, e = m.command(ctx, "resolvectl", "revert", s.Name)
		}
		if e != nil {
			failures = append(failures, e)
		} else {
			s.DNSMethod = ""
		}
	}
	if s.Routing {
		routeFailed := false
		for _, family := range []string{"-4", "-6"} {
			rs, e := m.rules(ctx, family)
			if e != nil {
				failures = append(failures, e)
				routeFailed = true
				continue
			}
			for _, r := range rs {
				if ownedRule(r) && (r.Priority != 10902 || r.Input == s.Name) {
					args := []string{family, "rule", "del", "pref", strconv.Itoa(r.Priority), "table", scalar(r.Table), "protocol", Protocol}
					if r.Priority == 10900 {
						args = append(args, "fwmark", MarkText)
					}
					if r.Input != "" {
						args = append(args, "iif", r.Input)
					}
					if _, e = m.command(ctx, "ip", args...); e != nil {
						failures = append(failures, e)
						routeFailed = true
					}
				}
			}
			routes, e := m.routes(ctx, family)
			if e != nil {
				failures = append(failures, e)
				routeFailed = true
				continue
			}
			for _, r := range routes {
				if scalar(r.Table) == Table && scalar(r.Protocol) == Protocol && ((r.Destination == "default" && r.Device == s.Name) || r.Type == "throw") {
					args := []string{family, "route", "del"}
					if r.Type == "throw" {
						args = append(args, "throw", r.Destination)
					} else {
						args = append(args, "default", "dev", s.Name)
					}
					args = append(args, "table", Table, "proto", Protocol)
					if _, e = m.command(ctx, "ip", args...); e != nil {
						failures = append(failures, e)
						routeFailed = true
					}
				}
			}
		}
		if !routeFailed {
			s.Routing = false
		}
	}
	// Keep protection if another cleanup operation failed.
	if s.Guard && !preserveGuard && len(failures) == 0 {
		present, e := m.guardPresent(ctx)
		if e == nil && present {
			_, e = m.command(ctx, "nft", "delete", "table", "inet", FirewallTable)
		}
		if e != nil {
			failures = append(failures, e)
		} else {
			s.Guard = false
		}
	}
	if e := m.save(s); e != nil {
		failures = append(failures, e)
	}
	if len(failures) == 0 && !s.Guard {
		return os.Remove(filepath.Join(m.Dir, "state.json"))
	}
	return errors.Join(failures...)
}

func (m *Manager) BootstrapDNS(ctx context.Context, device string) []string {
	b, _ := os.ReadFile(m.Resolver)
	if s, err := m.Load(); err == nil && s != nil && s.DNSMethod == "file" && bytes.Equal(b, s.DNSInstalled) {
		b = s.DNSOriginal
	}
	dns := nameservers(string(b))
	if len(dns) == 0 {
		out, err := m.command(ctx, "resolvectl", "dns", device)
		if err == nil {
			for _, f := range strings.Fields(string(out)) {
				if a, e := netip.ParseAddr(f); e == nil && a.Is4() && !a.IsLoopback() {
					dns = append(dns, a.String())
				}
			}
		}
	}
	return dns
}
func nameservers(text string) []string {
	var result []string
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			a, e := netip.ParseAddr(f[1])
			if e == nil && a.Is4() && !a.IsLoopback() && a.String() != "198.18.0.2" {
				result = append(result, a.String())
			}
		}
	}
	return result
}
