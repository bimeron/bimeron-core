package routing

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

// Decoder limits bound allocations and work on untrusted local dataset bytes.
const (
	maxGeoBytes      = 64 << 20
	maxGeoEntries    = 2_000_000
	maxGeoGroups     = 100_000
	maxGeoRegex      = 10_000
	maxGeoRegexBytes = 1 << 20
	maxGeoString     = 4096
)

// GeoDataError locates a dataset or active rule failure. Rule is one-based;
// zero means decoding, outside a rule. Kind is "geoip" or "geosite";
// Group may be empty for framing errors. Err is excluded from JSON.
type GeoDataError struct {
	Code  string `json:"code"`
	Kind  string `json:"kind"`
	Group string `json:"group,omitempty"`
	Rule  int    `json:"rule,omitempty"`
	Err   error  `json:"-"`
}

func (e *GeoDataError) Error() string {
	location := e.Kind
	if e.Group != "" {
		location += fmt.Sprintf(" group %q", e.Group)
	}
	if e.Rule > 0 {
		location += fmt.Sprintf(" rule %d", e.Rule)
	}
	if e.Err == nil {
		return location + ": " + e.Code
	}
	return location + ": " + e.Err.Error()
}
func (e *GeoDataError) Unwrap() error { return e.Err }

// GeoData is an immutable decoded V2Ray GeoIPList/GeoSiteList snapshot.
// Schemas: https://github.com/v2fly/v2ray-core/blob/v4.45.2/app/router/config.proto
// https://github.com/v2fly/v2ray-core/blob/master/app/router/routercommon/common.proto
// GeoIP field 3 is the inverse/reverse match flag; domain types are 0..3.
type GeoData struct {
	ips   map[string]*ipGroup
	sites map[string]*domainGroup
}
type ipGroup struct {
	prefixes map[netip.Prefix]struct{}
	reverse  bool
}
type domainGroup struct {
	full, roots map[string]struct{}
	plain       []string
	regex       []*regexp.Regexp
}

func (g *ipGroup) matches(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	found := false
	for bits := ip.BitLen(); bits >= 0; bits-- {
		if _, ok := g.prefixes[netip.PrefixFrom(ip, bits).Masked()]; ok {
			found = true
			break
		}
	}
	return found != g.reverse
}
func (g *domainGroup) matches(s string) bool {
	if s == "" {
		return false
	}
	if _, ok := g.full[s]; ok {
		return true
	}
	for tail := s; ; {
		if _, ok := g.roots[tail]; ok {
			return true
		}
		i := strings.IndexByte(tail, '.')
		if i < 0 {
			break
		}
		tail = tail[i+1:]
	}
	// ponytail: Plain and Regex scan bounded entries; add a text index if profiling justifies it.
	for _, v := range g.plain {
		if strings.Contains(s, v) {
			return true
		}
	}
	for _, v := range g.regex {
		if v.MatchString(s) {
			return true
		}
	}
	return false
}

var (
	errGeoLimit      = errors.New("geodata resource limit exceeded")
	errGeoIdentifier = errors.New("invalid geodata identifier")
)

func geoError(kind, group string, rule int, err error) *GeoDataError {
	code := "geodata_invalid"
	if errors.Is(err, errGeoLimit) {
		code = "geodata_limit"
	}
	if errors.Is(err, errGeoIdentifier) {
		code = "geodata_identifier_invalid"
	}
	return &GeoDataError{Code: code, Kind: strings.ToLower(kind), Group: group, Rule: rule, Err: err}
}

type regexBudget struct{ count, bytes int }

// Groups returns sorted lowercase identifiers. kind is GeoIP or GeoSite
// (case insensitive). The returned slice is detached from the dataset.
func (d *GeoData) Groups(kind string) ([]string, error) {
	var names []string
	switch strings.ToLower(kind) {
	case "geoip":
		if d != nil {
			for k := range d.ips {
				names = append(names, k)
			}
		}
	case "geosite":
		if d != nil {
			for k := range d.sites {
				names = append(names, k)
			}
		}
	default:
		return nil, geoError("", "", 0, fmt.Errorf("unknown geodata kind"))
	}
	sort.Strings(names)
	return names, nil
}

// fields validates wire framing, including unknown fields, without recursion.
// Deprecated protobuf groups are deliberately rejected.
func fields(b []byte, visit func(protowire.Number, protowire.Type, []byte, uint64) error) error {
	for len(b) > 0 {
		n, t, k := protowire.ConsumeTag(b)
		if k < 0 || n < 1 || n > protowire.MaxValidNumber {
			return fmt.Errorf("invalid protobuf tag")
		}
		b = b[k:]
		var raw []byte
		var v uint64
		switch t {
		case protowire.VarintType:
			v, k = protowire.ConsumeVarint(b)
		case protowire.BytesType:
			raw, k = protowire.ConsumeBytes(b)
		case protowire.Fixed32Type:
			k = 4
		case protowire.Fixed64Type:
			k = 8
		default:
			return fmt.Errorf("unsupported protobuf wire type %d", t)
		}
		if k < 0 || k > len(b) {
			return fmt.Errorf("truncated protobuf field")
		}
		if err := visit(n, t, raw, v); err != nil {
			return err
		}
		b = b[k:]
	}
	return nil
}
func wire(got, want protowire.Type) error {
	if got != want {
		return fmt.Errorf("invalid protobuf field wire type")
	}
	return nil
}
func geoString(b []byte) (string, error) {
	if len(b) > maxGeoString {
		return "", errGeoLimit
	}
	if len(b) == 0 || !utf8.Valid(b) {
		return "", fmt.Errorf("invalid geodata string")
	}
	return string(b), nil
}
func groupID(s string) (string, error) {
	s = strings.ToLower(s)
	if s == "" || len(s) > 256 {
		return "", errGeoIdentifier
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", errGeoIdentifier
		}
	}
	return s, nil
}

// DecodeGeoData accepts standard V2Ray protobuf datasets. Empty bytes mean an
// unavailable dataset. A well-framed file with no groups is also unavailable.
// Attributes and unknown scalar/length-delimited fields
// are ignored; attribute selectors in rule identifiers are not supported.
// Inputs are never retained and no files are opened.
func DecodeGeoData(geoIP, geoSite []byte) (*GeoData, error) {
	d := &GeoData{ips: map[string]*ipGroup{}, sites: map[string]*domainGroup{}}
	budget := maxGeoEntries
	groups := maxGeoGroups
	regexes := &regexBudget{}
	for kind, input := range [][]byte{geoIP, geoSite} {
		if len(input) > maxGeoBytes {
			return nil, geoError([]string{"GeoIP", "GeoSite"}[kind], "", 0, errGeoLimit)
		}
		err := fields(input, func(n protowire.Number, t protowire.Type, b []byte, _ uint64) error {
			if n != 1 {
				return nil
			}
			if err := wire(t, protowire.BytesType); err != nil {
				return err
			}
			groups--
			if groups < 0 {
				return errGeoLimit
			}
			budget--
			if budget < 0 {
				return errGeoLimit
			}
			var id string
			ig := &ipGroup{prefixes: map[netip.Prefix]struct{}{}}
			dg := &domainGroup{full: map[string]struct{}{}, roots: map[string]struct{}{}}
			err := fields(b, func(n protowire.Number, t protowire.Type, b []byte, v uint64) error {
				switch n {
				case 1:
					if err := wire(t, protowire.BytesType); err != nil {
						return err
					}
					s, err := geoString(b)
					if err != nil {
						return err
					}
					id, err = groupID(s)
					return err
				case 2:
					if err := wire(t, protowire.BytesType); err != nil {
						return err
					}
					budget--
					if budget < 0 {
						return errGeoLimit
					}
					if kind == 0 {
						p, err := decodeCIDR(b)
						if err == nil {
							ig.prefixes[p] = struct{}{}
						}
						return err
					}
					return decodeDomain(b, dg, regexes)
				case 3:
					if kind == 0 {
						if err := wire(t, protowire.VarintType); err != nil {
							return err
						}
						if v > 1 {
							return fmt.Errorf("invalid reverse match flag")
						}
						ig.reverse = v == 1
					}
				}
				return nil
			})
			if err != nil {
				return geoError([]string{"GeoIP", "GeoSite"}[kind], id, 0, err)
			}
			if id == "" {
				return fmt.Errorf("missing geodata identifier")
			}
			if kind == 0 {
				if _, ok := d.ips[id]; ok {
					return fmt.Errorf("duplicate GeoIP group %q", id)
				}
				d.ips[id] = ig
			} else {
				if _, ok := d.sites[id]; ok {
					return fmt.Errorf("duplicate GeoSite group %q", id)
				}
				d.sites[id] = dg
			}
			return nil
		})
		if err != nil {
			if _, ok := err.(*GeoDataError); ok {
				return nil, err
			}
			return nil, geoError([]string{"GeoIP", "GeoSite"}[kind], "", 0, err)
		}
	}
	return d, nil
}
func decodeCIDR(b []byte) (netip.Prefix, error) {
	var ip netip.Addr
	var bits uint64
	err := fields(b, func(n protowire.Number, t protowire.Type, b []byte, v uint64) error {
		switch n {
		case 1:
			if err := wire(t, protowire.BytesType); err != nil {
				return err
			}
			var ok bool
			ip, ok = netip.AddrFromSlice(b)
			if !ok {
				return fmt.Errorf("CIDR address must have 4 or 16 bytes")
			}
		case 2:
			if err := wire(t, protowire.VarintType); err != nil {
				return err
			}
			bits = v
		}
		return nil
	})
	if err != nil {
		return netip.Prefix{}, err
	}
	if !ip.IsValid() || bits > uint64(ip.BitLen()) {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR prefix")
	}
	// Match policy's IPv4-mapped address normalization without changing v6 /0.
	if ip.Is4In6() && bits >= 96 {
		ip = ip.Unmap()
		bits -= 96
	}
	return netip.PrefixFrom(ip, int(bits)).Masked(), nil
}
func decodeDomain(b []byte, g *domainGroup, budget *regexBudget) error {
	var typ uint64
	var value string
	err := fields(b, func(n protowire.Number, t protowire.Type, b []byte, v uint64) error {
		switch n {
		case 1:
			if err := wire(t, protowire.VarintType); err != nil {
				return err
			}
			typ = v
		case 2:
			if err := wire(t, protowire.BytesType); err != nil {
				return err
			}
			var err error
			value, err = geoString(b)
			return err
		case 3:
			if err := wire(t, protowire.BytesType); err != nil {
				return err
			}
			return fields(b, func(n protowire.Number, t protowire.Type, b []byte, _ uint64) error {
				switch n {
				case 1:
					if err := wire(t, protowire.BytesType); err != nil {
						return err
					}
					_, err := geoString(b)
					return err
				case 2, 3:
					return wire(t, protowire.VarintType)
				}
				return nil
			})
		}
		return nil
	})
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("empty geosite domain")
	}
	switch typ {
	case 0:
		g.plain = append(g.plain, strings.ToLower(value))
	case 1:
		budget.count++
		budget.bytes += len(value)
		if budget.count > maxGeoRegex || budget.bytes > maxGeoRegexBytes {
			return errGeoLimit
		}
		r, err := regexp.Compile(value)
		if err != nil {
			return fmt.Errorf("invalid geosite regex")
		}
		g.regex = append(g.regex, r)
	case 2, 3:
		value = normalize(value)
		if value == "" || strings.ContainsAny(value, " /*:\t\r\n") {
			return fmt.Errorf("invalid geosite domain")
		}
		if typ == 2 {
			g.roots[value] = struct{}{}
		} else {
			g.full[value] = struct{}{}
		}
	default:
		return fmt.Errorf("unsupported geosite domain type %d", typ)
	}
	return nil
}
