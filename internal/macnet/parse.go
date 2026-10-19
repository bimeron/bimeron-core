// Package macnet isolates macOS network commands and recovery journals.
package macnet

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const TunnelDNS = "198.18.0.2"

var ErrNetworkUnavailable = fmt.Errorf("network_unavailable")
var ErrDNSConflict = fmt.Errorf("macos_dns_changed_externally")

type Route struct {
	Prefix  string
	Device  string
	Index   int
	Gateway string
	Scoped  bool
}

func CaptureRoutes() []string {
	return []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "198.18.0.2/32"}
}
func validTunnel(s string) bool { return regexp.MustCompile(`^utun[0-9]+$`).MatchString(s) }
func validServiceID(s string) bool {
	return regexp.MustCompile(`^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$`).MatchString(s)
}
func dictionaryValue(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		left, right, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.TrimSpace(left) == key {
			return strings.TrimSpace(right)
		}
	}
	return ""
}
func ParseDefaultRoute(text string) (device, gateway string, err error) {
	device = dictionaryValue(text, "interface")
	gateway = dictionaryValue(text, "gateway")
	if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`).MatchString(device) || strings.HasPrefix(device, "utun") || strings.HasPrefix(device, "ipsec") || device == "lo0" {
		return "", "", ErrNetworkUnavailable
	}
	if a, e := netip.ParseAddr(gateway); e != nil || !a.Is4() {
		return "", "", ErrNetworkUnavailable
	}
	return device, gateway, nil
}
func normalizePrefix(s string) string {
	if p, e := netip.ParsePrefix(s); e == nil {
		return p.Masked().String()
	}
	if a, e := netip.ParseAddr(s); e == nil && a.Zone() == "" {
		return netip.PrefixFrom(a, a.BitLen()).String()
	}
	ip, bits, ok := strings.Cut(s, "/")
	if !ok || strings.Contains(ip, ":") {
		return ""
	}
	octets := strings.Split(ip, ".")
	if len(octets) > 4 {
		return ""
	}
	for len(octets) < 4 {
		octets = append(octets, "0")
	}
	if p, e := netip.ParsePrefix(strings.Join(octets, ".") + "/" + bits); e == nil {
		return p.Masked().String()
	}
	return ""
}
func ParseRoutes(text string) ([]Route, error) {
	var result []Route
	column := -1
	headerFound := false
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Destination" {
			column = -1
			for i, f := range fields {
				if f == "Netif" || f == "Iface" {
					column = i
				}
			}
			headerFound = column >= 0
			continue
		}
		if column < 0 || len(fields) <= column {
			continue
		}
		prefix := normalizePrefix(fields[0])
		if fields[0] == "default" {
			prefix = "0.0.0.0/0"
			if strings.Contains(text, "Internet6:") {
				prefix = "::/0"
			}
		}
		if prefix == "" {
			continue
		}
		row := Route{Prefix: prefix, Device: fields[column], Gateway: fields[1], Scoped: len(fields) > 2 && strings.Contains(fields[2], "I")}
		if strings.HasPrefix(fields[1], "link#") {
			row.Index, _ = strconv.Atoi(strings.TrimPrefix(fields[1], "link#"))
		}
		result = append(result, row)
	}
	if !headerFound {
		return nil, fmt.Errorf("unrecognized macOS routing table")
	}
	return result, nil
}
func ParseExplicitDNS(text string) ([]string, error) {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "There aren't any DNS Servers set on ") {
		return nil, nil
	}
	var result []string
	for _, line := range strings.Split(text, "\n") {
		a, e := netip.ParseAddr(strings.TrimSpace(line))
		if e != nil {
			return nil, fmt.Errorf("cannot read network service DNS")
		}
		result = append(result, a.String())
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("empty networksetup DNS response")
	}
	return result, nil
}
func ParseDefaultDNS(text string) []string {
	var block []string
	supplemental := false
	flush := func() []string {
		if !supplemental && len(block) > 0 {
			return unique(block)
		}
		block = nil
		supplemental = false
		return nil
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "DNS configuration (for scoped queries)") {
			return flush()
		}
		if strings.HasPrefix(line, "resolver #") {
			if result := flush(); len(result) > 0 {
				return result
			}
			continue
		}
		if strings.HasPrefix(line, "domain") {
			supplemental = true
		}
		if strings.HasPrefix(line, "nameserver[") {
			_, value, ok := strings.Cut(line, ":")
			if ok {
				if address, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil {
					block = append(block, address.String())
				}
			}
		}
	}
	return flush()
}
func ParseBootstrapDNS(text, device string) []string {
	var global, scoped, block []string
	iface := ""
	supplemental := false
	flush := func() {
		if iface == device {
			scoped = append(scoped, block...)
		} else if iface == "" && !supplemental {
			global = append(global, block...)
		}
		block = nil
		iface = ""
		supplemental = false
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "resolver #") {
			flush()
			continue
		}
		if strings.HasPrefix(line, "domain") {
			supplemental = true
		}
		if strings.HasPrefix(line, "nameserver[") {
			_, value, ok := strings.Cut(line, ":")
			if ok {
				a, e := netip.ParseAddr(strings.TrimSpace(value))
				if e == nil && a.Is4() && !a.IsLoopback() && a.String() != TunnelDNS {
					block = append(block, a.String())
				}
			}
		}
		if strings.HasPrefix(line, "if_index") {
			start, end := strings.Index(line, "("), strings.Index(line, ")")
			if start >= 0 && end > start {
				iface = line[start+1 : end]
			}
		}
	}
	flush()
	if len(scoped) > 0 {
		return unique(scoped)
	}
	return unique(global)
}
func unique(values []string) []string {
	var result []string
	seen := map[string]bool{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
