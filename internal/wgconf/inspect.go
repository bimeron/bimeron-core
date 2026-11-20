package wgconf

import (
	"net/netip"
	"slices"
	"strings"
)

// awgIntroduced maps each AmneziaWG option to the version introducing it.
var awgIntroduced = map[string]string{
	"Jc": "1.0", "Jmin": "1.0", "Jmax": "1.0", "S1": "1.0", "S2": "1.0",
	"H1": "1.0", "H2": "1.0", "H3": "1.0", "H4": "1.0",
	"I1": "1.5", "I2": "1.5", "I3": "1.5", "I4": "1.5", "I5": "1.5",
	"S3": "2.0", "S4": "2.0",
	"HeaderProtectionKey": "3.0", "ContentPaddingAddition": "3.0", "RekeyAfterTime": "3.0",
	"RekeyTimeout": "3.0", "RejectAfterTime": "3.0", "KeepaliveTimeout": "3.0", "MaxHandshakeAttempts": "3.0",
	"RandomTrailers": "3.1", "DisableCookies": "3.1",
}

// Protocol reports the protocol and the minimum AmneziaWG version implied by
// the options present, without validating them. Plain WireGuard has "".
func (d *Document) Protocol() (protocol, version string) {
	rank := -1
	raise := func(v string) { rank = max(rank, slices.Index(AWGVersions, v)) }
	for _, l := range d.lines {
		if !l.known || l.value == "" {
			continue
		}
		if v, ok := awgIntroduced[l.key]; ok {
			raise(v)
			if strings.HasPrefix(l.key, "H") && strings.Contains(l.value, "-") {
				raise("2.0")
			}
		}
		if l.key == "PersistentKeepalive" && strings.Contains(l.value, "-") {
			raise("3.0")
		}
	}
	if rank < 0 {
		return ProtocolWireGuard, ""
	}
	return ProtocolAmneziaWG, AWGVersions[rank]
}

// Coverage values.
const (
	CoverageFull     = "full"
	CoveragePartial  = "partial"
	CoverageNone     = "none"
	CoverageIPv4Only = "ipv4_only"
)

// AllowedIPs summarizes the peer's AllowedIPs. Prefixes keep text order.
type AllowedIPs struct {
	Prefixes []string `json:"prefixes"`
	IPv4     string   `json:"ipv4"`
	IPv6     string   `json:"ipv6"`
	Coverage string   `json:"coverage"`
}

// Summarize computes per-family coverage of the union of prefixes.
func Summarize(prefixes []netip.Prefix) AllowedIPs {
	s := AllowedIPs{Prefixes: []string{}}
	for _, p := range prefixes {
		s.Prefixes = append(s.Prefixes, p.String())
	}
	s.IPv4 = familyCoverage(prefixes, false)
	s.IPv6 = familyCoverage(prefixes, true)
	switch {
	case s.IPv4 == CoverageFull && s.IPv6 == CoverageFull:
		s.Coverage = CoverageFull
	case s.IPv4 == CoverageFull:
		s.Coverage = CoverageIPv4Only
	default:
		s.Coverage = CoveragePartial
	}
	return s
}

func familyCoverage(prefixes []netip.Prefix, v6 bool) string {
	var family []netip.Prefix
	for _, p := range prefixes {
		if p.Addr().Is6() == v6 {
			family = append(family, p.Masked())
		}
	}
	if len(family) == 0 {
		return CoverageNone
	}
	if Covers(family, v6) {
		return CoverageFull
	}
	return CoveragePartial
}

// Covers reports whether the prefixes jointly cover their whole family.
func Covers(prefixes []netip.Prefix, v6 bool) bool {
	root := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	if v6 {
		root = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return covered(root, prefixes)
}

// covered splits target until every half is inside some prefix. Depth is
// bounded by the address length and the recursion only follows halves that
// still intersect a more specific prefix.
func covered(target netip.Prefix, prefixes []netip.Prefix) bool {
	var inside []netip.Prefix
	for _, p := range prefixes {
		if p.Bits() <= target.Bits() && p.Contains(target.Addr()) {
			return true
		}
		if p.Bits() > target.Bits() && target.Contains(p.Addr()) {
			inside = append(inside, p)
		}
	}
	if len(inside) == 0 || target.Bits() == target.Addr().BitLen() {
		return false
	}
	low, high := halves(target)
	return covered(low, inside) && covered(high, inside)
}

func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	low := netip.PrefixFrom(p.Addr(), bits).Masked()
	b := low.Addr().AsSlice()
	b[(bits-1)/8] |= 0x80 >> ((bits - 1) % 8)
	a, _ := netip.AddrFromSlice(b)
	return low, netip.PrefixFrom(a, bits)
}

// DocumentAllowedIPs collects syntactically valid AllowedIPs entries of the
// first [Peer] for display, ignoring invalid items.
func (d *Document) AllowedIPs() []netip.Prefix {
	var out []netip.Prefix
	for _, l := range d.lines {
		if !l.known || l.key != "AllowedIPs" || d.sections[l.section].name != Peer {
			continue
		}
		for _, item := range listItems(l.value) {
			if p, ok := parsePrefix(item); ok {
				out = append(out, p.Masked())
			}
		}
	}
	return out
}
