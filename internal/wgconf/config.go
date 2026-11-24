package wgconf

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"bimeron/internal/problem"
)

// Protocol names reported by Inspect.
const (
	ProtocolWireGuard = "wireguard"
	ProtocolAmneziaWG = "amneziawg"
)

// AWGVersions lists the AmneziaWG versions Bimeron accepts, oldest first.
var AWGVersions = []string{"1.0", "1.5", "2.0", "3.0", "3.1"}

// DefaultMTU is the tunnel MTU when the text omits MTU.
const DefaultMTU = 1420

// Key is a Curve25519 or symmetric key. It must never be logged.
type Key [32]byte

func (k Key) hex() string { return hex.EncodeToString(k[:]) }

// IsZero reports an unset key.
func (k Key) IsZero() bool { return k == Key{} }

// Range is an inclusive unsigned range; Lo == Hi for a single value.
type Range struct{ Lo, Hi uint32 }

func (r Range) String() string {
	if r.Lo == r.Hi {
		return strconv.FormatUint(uint64(r.Lo), 10)
	}
	return strconv.FormatUint(uint64(r.Lo), 10) + "-" + strconv.FormatUint(uint64(r.Hi), 10)
}

func (r Range) overlaps(o Range) bool { return r.Lo <= o.Hi && o.Lo <= r.Hi }

// Config is a validated single-peer WireGuard or AmneziaWG client.
type Config struct {
	PrivateKey Key
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int
	ListenPort int
	// AWG holds validated AmneziaWG options by canonical key, in AWGKeys order.
	AWG  map[string]string
	Peer PeerConfig
}

// PeerConfig is the only peer of a client configuration.
type PeerConfig struct {
	PublicKey    Key
	PresharedKey Key
	Reserved     [3]byte
	// EndpointHost is an IP literal or a DNS name; EndpointPort is 1-65535.
	EndpointHost string
	EndpointPort int
	AllowedIPs   []netip.Prefix
	// Keepalive is zero when persistent keepalive is off.
	Keepalive            Range
	keepaliveRangeSyntax bool
}

// Protocol reports amneziawg when any AmneziaWG option or an AWG 3
// keepalive range is set, matching Document.Protocol.
func (c *Config) Protocol() string {
	if len(c.AWG) > 0 || c.Peer.keepaliveRangeSyntax || c.Peer.Keepalive.Lo != c.Peer.Keepalive.Hi {
		return ProtocolAmneziaWG
	}
	return ProtocolWireGuard
}

// TunnelMTU returns the configured or default tunnel MTU.
func (c *Config) TunnelMTU() int {
	if c.MTU == 0 {
		return DefaultMTU
	}
	return c.MTU
}

// Endpoint returns host:port for the peer endpoint.
func (c *Config) Endpoint() string {
	return net.JoinHostPort(c.Peer.EndpointHost, strconv.Itoa(c.Peer.EndpointPort))
}

// LocalAddresses returns the tunnel interface addresses.
func (c *Config) LocalAddresses() []netip.Addr {
	out := make([]netip.Addr, 0, len(c.Addresses))
	for _, p := range c.Addresses {
		out = append(out, p.Addr())
	}
	return out
}

// uapiKeys maps AWG options to the engine's configuration protocol keys.
var uapiKeys = map[string]string{
	"Jc": "jc", "Jmin": "jmin", "Jmax": "jmax",
	"S1": "s1", "S2": "s2", "S3": "s3", "S4": "s4",
	"H1": "h1", "H2": "h2", "H3": "h3", "H4": "h4",
	"I1": "i1", "I2": "i2", "I3": "i3", "I4": "i4", "I5": "i5",
	"HeaderProtectionKey": "header_protection_key", "ContentPaddingAddition": "content_padding_addition",
	"RekeyAfterTime": "rekey_after_time", "RekeyTimeout": "rekey_timeout", "RejectAfterTime": "reject_after_time",
	"KeepaliveTimeout": "keepalive_timeout", "MaxHandshakeAttempts": "max_handshake_attempts",
	"RandomTrailers": "random_trailers", "DisableCookies": "disable_cookies",
}

// UAPI returns the engine configuration with endpoint as a resolved IP:port
// and allowed as the peer's allowed prefixes. The result holds secrets.
func (c *Config) UAPI(endpoint netip.AddrPort, allowed []netip.Prefix) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", c.PrivateKey.hex())
	if c.ListenPort != 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	}
	for _, key := range AWGKeys {
		value, ok := c.AWG[key]
		if !ok {
			continue
		}
		if key == "HeaderProtectionKey" {
			k, _ := parseKey(value)
			value = k.hex()
		}
		fmt.Fprintf(&b, "%s=%s\n", uapiKeys[key], value)
	}
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", c.Peer.PublicKey.hex())
	if !c.Peer.PresharedKey.IsZero() {
		fmt.Fprintf(&b, "preshared_key=%s\n", c.Peer.PresharedKey.hex())
	}
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint.String())
	if c.Peer.Keepalive != (Range{}) {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%s\n", c.Peer.Keepalive.String())
	}
	b.WriteString("replace_allowed_ips=true\n")
	for _, p := range allowed {
		fmt.Fprintf(&b, "allowed_ip=%s\n", p.String())
	}
	return b.String()
}

// Parse validates WireGuard text. The returned problem carries Document,
// Section, Field and the one-based Line inside the text.
func Parse(text string) (*Config, error) {
	d, err := ParseDocument(text)
	if err != nil {
		return nil, err
	}
	return d.Config()
}

// Config validates the document and returns the runnable configuration.
func (d *Document) Config() (*Config, error) {
	if err := d.validateStructure(); err != nil {
		return nil, err
	}
	c := &Config{AWG: map[string]string{}}
	at := map[string]int{}
	for i, l := range d.lines {
		if l.header || l.section < 0 || content(l.raw) == "" {
			continue
		}
		name := d.sections[l.section].name
		at[name+"/"+l.key] = i + 1
		fail := func(p *problem.Error) error {
			return p.In(name).At(l.key).AtLine(i + 1).InDocument(DocumentName)
		}
		if l.value == "" {
			if requiredKeys[l.key] {
				return nil, fail(problem.New("value_required", "WireGuard option requires a value").On(l.key, ""))
			}
			continue
		}
		if err := c.set(name, l.key, l.value); err != nil {
			return nil, fail(problem.Of(err))
		}
	}
	for _, key := range []string{"Interface/PrivateKey", "Interface/Address", "Peer/PublicKey", "Peer/Endpoint", "Peer/AllowedIPs"} {
		section, field, _ := strings.Cut(key, "/")
		if _, ok := at[key]; !ok || (field == "Address" && len(c.Addresses) == 0) || (field == "AllowedIPs" && len(c.Peer.AllowedIPs) == 0) {
			p := problem.New("value_required", "WireGuard option is required").In(section).On(field, "").InDocument(DocumentName)
			for i, s := range d.sections {
				if s.known && s.name == section {
					p.AtLine(d.sections[i].line + 1)
				}
			}
			return nil, p
		}
	}
	if err := c.validateCombinations(); err != nil {
		p := problem.Of(err).InDocument(DocumentName)
		if line := at[p.Section+"/"+p.Field]; line > 0 {
			p.AtLine(line)
		}
		return nil, p
	}
	return c, nil
}

func parseReserved(value string) ([3]byte, error) {
	var reserved [3]byte
	invalid := func() ([3]byte, error) {
		return [3]byte{}, problem.New("number_invalid", "WireGuard Reserved must contain three comma-separated decimal bytes (0–255)")
	}
	parts := strings.Split(value, ",")
	if len(parts) != len(reserved) {
		return invalid()
	}
	for i, part := range parts {
		n, err := strconv.ParseUint(strings.TrimSpace(part), 10, 8)
		if err != nil {
			return invalid()
		}
		reserved[i] = byte(n)
	}
	return reserved, nil
}

var requiredKeys = map[string]bool{"PrivateKey": true, "Address": true, "PublicKey": true, "Endpoint": true, "AllowedIPs": true}

// validateStructure rejects layout problems before values are checked.
func (d *Document) validateStructure() error {
	for i, l := range d.lines {
		at := func(p *problem.Error) error { return p.AtLine(i + 1).InDocument(DocumentName) }
		switch {
		case l.malformed:
			return at(problem.New("syntax_invalid", "invalid WireGuard configuration line"))
		case l.header && !d.sections[l.section].known:
			return at(problem.New("section_unknown", "unknown WireGuard section"))
		case l.header || l.section < 0 || content(l.raw) == "":
		case !l.known:
			name := d.sections[l.section].name
			return at(unknownKey(name, l.key))
		}
	}
	if err := d.structureError(); err != nil {
		return err
	}
	peers := 0
	for _, s := range d.sections {
		if s.name == Peer {
			peers++
		}
	}
	if peers != 1 {
		return problem.New("wireguard_peer_count", "WireGuard profiles support exactly one [Peer]").ArgInt("count", peers).InDocument(DocumentName)
	}
	for _, s := range d.sections {
		if s.name == Interface {
			return nil
		}
	}
	return problem.New("value_required", "WireGuard [Interface] section is required").In(Interface).InDocument(DocumentName)
}

// unknownKey classifies an unrecognized option without echoing it unless it
// is a known wg-quick option name.
func unknownKey(section, key string) *problem.Error {
	for _, hook := range []string{"PreUp", "PostUp", "PreDown", "PostDown"} {
		if strings.EqualFold(hook, key) {
			return problem.New("wireguard_hook_unsupported", "WireGuard hook commands are not supported").In(section).At(hook)
		}
	}
	for _, option := range []string{"Table", "FwMark", "SaveConfig"} {
		if strings.EqualFold(option, key) {
			return problem.New("option_not_supported", "WireGuard option is not supported").In(section).At(option).Arg("type", "WireGuard")
		}
	}
	return problem.New("option_unknown", "unknown WireGuard option").In(section)
}

func parseKey(value string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(b) != len(k) {
		return k, problem.New("wireguard_key_invalid", "WireGuard keys must be 32 bytes in base64")
	}
	copy(k[:], b)
	return k, nil
}

func listItems(value string) []string {
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// parsePrefix accepts a prefix or a bare address (a host prefix).
func parsePrefix(value string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(value); err == nil && !p.Addr().Is4In6() && p.Addr().Zone() == "" {
		return p, true
	}
	if a, err := netip.ParseAddr(value); err == nil && !a.Is4In6() && a.Zone() == "" {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func parseUint(value string, max uint64) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || (len(value) > 1 && value[0] == '0') {
		return 0, problem.New("number_invalid", "invalid WireGuard number")
	}
	if n > max {
		return 0, problem.New("number_out_of_range", "WireGuard number out of range").Arg("min", "0").Arg("max", strconv.FormatUint(max, 10))
	}
	return n, nil
}

func parseRange(value string, min, max uint64) (Range, error) {
	lo, hi, isRange := strings.Cut(value, "-")
	a, err := parseUint(lo, max)
	if err != nil {
		return Range{}, rangeArgs(err, min, max)
	}
	b := a
	if isRange {
		if b, err = parseUint(hi, max); err != nil {
			return Range{}, rangeArgs(err, min, max)
		}
	}
	if a < min {
		return Range{}, rangeArgs(problem.New("number_out_of_range", "WireGuard number out of range"), min, max)
	}
	if b < a {
		return Range{}, problem.New("awg_range_invalid", "range start must not exceed its end")
	}
	return Range{Lo: uint32(a), Hi: uint32(b)}, nil
}

func rangeArgs(err error, min, max uint64) error {
	p := problem.Of(err)
	if p.Code == "number_out_of_range" {
		p.Arg("min", strconv.FormatUint(min, 10)).Arg("max", strconv.FormatUint(max, 10))
	}
	return p
}

// Limits keep every generated datagram inside the engine's 65535-byte
// message buffers and a UDP payload.
const (
	maxDatagram = 65507
	maxJunk     = 128
	// maxPadding bounds ContentPaddingAddition before the MTU check.
	maxPadding = maxDatagram
)

// messageSizes are the unpadded WireGuard message sizes behind S1-S3; S4
// pads transport messages, checked against the tunnel MTU.
var messageSizes = map[string]uint64{"S1": 148, "S2": 92, "S3": 64, "S4": 32}

func errZeroKey() error {
	return problem.New("wireguard_key_invalid", "WireGuard key must not be all zero")
}

func (c *Config) set(section, key, value string) error {
	switch section + "/" + key {
	case "Interface/PrivateKey":
		k, err := parseKey(value)
		if err == nil && k.IsZero() {
			return errZeroKey()
		}
		c.PrivateKey = k
		return err
	case "Interface/Address":
		for _, item := range listItems(value) {
			p, ok := parsePrefix(item)
			if !ok {
				return problem.New("wireguard_address_invalid", "WireGuard Address must list IP addresses or prefixes")
			}
			for _, old := range c.Addresses {
				if old.Addr() == p.Addr() {
					return problem.New("wireguard_address_invalid", "duplicate WireGuard address")
				}
			}
			c.Addresses = append(c.Addresses, p)
		}
	case "Interface/DNS":
		for _, item := range listItems(value) {
			a, err := netip.ParseAddr(item)
			if err != nil || a.Zone() != "" || a.Is4In6() || !a.IsValid() || a.IsUnspecified() {
				return problem.New("wireguard_dns_invalid", "WireGuard DNS must list IP addresses; search domains are not supported")
			}
			c.DNS = append(c.DNS, a)
		}
		if len(c.DNS) > 8 {
			return problem.New("dns_too_many", "WireGuard DNS supports at most 8 resolvers").Arg("max", "8")
		}
	case "Interface/MTU":
		n, err := parseRange(value, 576, 9000)
		if err == nil && n.Lo != n.Hi {
			err = problem.New("number_invalid", "invalid WireGuard number")
		}
		c.MTU = int(n.Lo)
		return err
	case "Interface/ListenPort":
		n, err := parseUint(value, 65535)
		c.ListenPort = int(n)
		return err
	case "Peer/PublicKey":
		k, err := parseKey(value)
		if err == nil && k.IsZero() {
			return errZeroKey()
		}
		c.Peer.PublicKey = k
		return err
	case "Peer/PresharedKey":
		k, err := parseKey(value)
		c.Peer.PresharedKey = k
		return err
	case "Peer/Endpoint":
		host, port, err := net.SplitHostPort(value)
		if err != nil || host == "" || strings.ContainsAny(host, " %/") {
			return problem.New("wireguard_endpoint_invalid", "WireGuard Endpoint must be host:port")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return problem.New("port_invalid", "invalid WireGuard endpoint port")
		}
		if a, err := netip.ParseAddr(host); err == nil {
			if a.Zone() != "" || a.IsUnspecified() {
				return problem.New("wireguard_endpoint_invalid", "WireGuard Endpoint must be host:port")
			}
			host = a.Unmap().String()
		} else if !validHostName(host) {
			return problem.New("host_invalid", "invalid WireGuard endpoint host")
		}
		c.Peer.EndpointHost, c.Peer.EndpointPort = host, n
	case "Peer/Reserved":
		reserved, err := parseReserved(value)
		c.Peer.Reserved = reserved
		return err
	case "Peer/AllowedIPs":
		for _, item := range listItems(value) {
			p, ok := parsePrefix(item)
			if !ok {
				return problem.New("wireguard_allowed_ips_invalid", "WireGuard AllowedIPs must list IP prefixes")
			}
			c.Peer.AllowedIPs = append(c.Peer.AllowedIPs, p.Masked())
		}
	case "Peer/PersistentKeepalive":
		if strings.EqualFold(value, "off") {
			c.Peer.Keepalive = Range{}
			return nil
		}
		r, err := parseRange(value, 0, 65535)
		c.Peer.Keepalive = r
		c.Peer.keepaliveRangeSyntax = strings.Contains(value, "-")
		return err
	default:
		canonical, err := awgValue(key, value)
		if err != nil {
			return err
		}
		c.AWG[key] = canonical
	}
	return nil
}

func validHostName(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// awgValue validates one AmneziaWG option and returns its canonical form.
func awgValue(key, value string) (string, error) {
	invalid := func(err error) error { return problem.Of(err).Arg("param", key) }
	switch key {
	case "Jc":
		n, err := parseUint(value, maxJunk)
		return strconv.FormatUint(n, 10), invalidArg(err, key)
	case "Jmin", "Jmax":
		n, err := parseUint(value, maxDatagram)
		return strconv.FormatUint(n, 10), invalidArg(err, key)
	case "S1", "S2", "S3", "S4":
		n, err := parseUint(value, maxDatagram-messageSizes[key])
		return strconv.FormatUint(n, 10), invalidArg(err, key)
	case "H1", "H2", "H3", "H4":
		r, err := parseRange(value, 0, 1<<32-1)
		return r.String(), invalidArg(err, key)
	case "I1", "I2", "I3", "I4", "I5":
		if err := validateTags(value); err != nil {
			return "", invalid(err)
		}
		return value, nil
	case "HeaderProtectionKey":
		k, err := parseKey(value)
		if err == nil && k.IsZero() {
			err = problem.New("wireguard_key_invalid", "header protection key must not be zero")
		}
		return value, err
	case "ContentPaddingAddition":
		r, err := parseRange(value, 0, maxPadding)
		return r.String(), invalidArg(err, key)
	case "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts":
		r, err := parseRange(value, 1, 1<<32-1)
		return r.String(), invalidArg(err, key)
	case "RandomTrailers", "DisableCookies":
		switch strings.ToLower(value) {
		// amneziawg-tools write on/off or 1/0.
		case "true", "on", "1":
			return "true", nil
		case "false", "off", "0":
			return "false", nil
		}
		return "", problem.New("boolean_invalid", "AmneziaWG option must be true, false, on, off, 1 or 0")
	}
	return "", problem.New("option_unknown", "unknown WireGuard option")
}

func invalidArg(err error, key string) error {
	if err == nil {
		return nil
	}
	return problem.Of(err).Arg("param", key)
}

// obfuscation tags accepted by the engine; values are byte counts or hex.
var tagKinds = map[string]bool{"b": true, "t": true, "r": true, "rc": true, "rd": true, "d": true, "ds": true, "dz": true}

// validateTags checks the I1-I5 tag grammar: a sequence of <tag [arg]>.
func validateTags(value string) error {
	_, err := signatureSize(value)
	return err
}

// signatureSize validates I1-I5 tags and returns the fixed bytes they add;
// data tags count only their size fields.
func signatureSize(value string) (int, error) {
	bad := func() (int, error) {
		return 0, problem.New("awg_tag_invalid", "invalid AmneziaWG signature packet tags")
	}
	total := 0
	rest := value
	for strings.TrimSpace(rest) != "" {
		rest = strings.TrimLeft(rest, " \t")
		if !strings.HasPrefix(rest, "<") {
			return bad()
		}
		end := strings.IndexByte(rest, '>')
		if end < 0 {
			return bad()
		}
		parts := strings.Fields(rest[1:end])
		rest = rest[end+1:]
		if len(parts) == 0 || len(parts) > 2 || !tagKinds[parts[0]] {
			return bad()
		}
		arg := ""
		if len(parts) == 2 {
			arg = parts[1]
		}
		switch parts[0] {
		case "b":
			b, err := hex.DecodeString(strings.TrimPrefix(arg, "0x"))
			if err != nil || len(b) == 0 {
				return bad()
			}
			total += len(b)
		case "t":
			if arg != "" {
				return bad()
			}
			total += 4
		case "r", "rc", "rd":
			n, err := strconv.Atoi(arg)
			if err != nil || n < 1 || n > maxDatagram {
				return bad()
			}
			total += n
		case "dz":
			// A size field of the given byte width.
			n, err := strconv.Atoi(arg)
			if err != nil || n < 1 || n > 8 {
				return bad()
			}
			total += n
		default:
			// <d> and <ds> carry the message itself and take no argument.
			if arg != "" {
				return bad()
			}
		}
		if total > maxDatagram {
			return bad()
		}
	}
	return total, nil
}

// PacketSizes reports the largest datagrams this configuration makes the
// engine build: a padded handshake message, a padded transport message at
// the tunnel MTU, a junk packet and a signature packet. Engines with smaller
// message buffers than the UDP limit must refuse larger sizes.
func (c *Config) PacketSizes() (handshake, transport, junk, signature int) {
	number := func(key string) int { n, _ := strconv.Atoi(c.AWG[key]); return n }
	for key, size := range map[string]int{"S1": 148, "S2": 92, "S3": 64} {
		handshake = max(handshake, size+number(key))
	}
	if c.AWG["RandomTrailers"] == "true" {
		// The engine pads handshakes with random trailers up to its initial
		// 500-byte UDP window; a larger observed window only follows larger
		// datagrams from the peer.
		handshake = max(handshake, 500)
	}
	// The engine aligns content to 16 bytes but never beyond the MTU, and
	// caps content padding and trailers by the UDP window: the largest
	// datagram observed from the peer, which our own receive limits already
	// bound. So a locally built transport message is header, tag, S4 and MTU,
	// plus padding only up to what the peer itself sent.
	transport = int(messageSizes["S4"]) + number("S4") + c.TunnelMTU()
	junk = number("Jmax")
	for i := 1; i <= 5; i++ {
		if n, err := signatureSize(c.AWG["I"+strconv.Itoa(i)]); err == nil {
			signature = max(signature, n)
		}
	}
	return handshake, transport, junk, signature
}

// defaultHeaders are the WireGuard message types used when H1-H4 are unset.
var defaultHeaders = [4]Range{{1, 1}, {2, 2}, {3, 3}, {4, 4}}

func (c *Config) validateCombinations() error {
	if c.Peer.Reserved != [3]byte{} && c.Protocol() == ProtocolAmneziaWG {
		return reservedWithAWG()
	}
	awg := func(code, message, field string) *problem.Error {
		return problem.New(code, message).In(Interface).At(field).Arg("param", field)
	}
	number := func(key string) uint64 { n, _ := strconv.ParseUint(c.AWG[key], 10, 64); return n }
	if _, ok := c.AWG["Jmin"]; ok || c.AWG["Jmax"] != "" {
		if number("Jmin") > number("Jmax") {
			return awg("awg_range_invalid", "Jmin must not exceed Jmax", "Jmin").Also("Jmax")
		}
	}
	headers := defaultHeaders
	for i := range headers {
		key := "H" + strconv.Itoa(i+1)
		if v, ok := c.AWG[key]; ok {
			r, _ := parseRange(v, 0, 1<<32-1)
			headers[i] = r
		}
	}
	for i := range headers {
		for j := i + 1; j < len(headers); j++ {
			if headers[i].overlaps(headers[j]) {
				return awg("awg_header_overlap", "AmneziaWG H1-H4 values must not overlap", "H"+strconv.Itoa(i+1)).Also("H" + strconv.Itoa(j+1))
			}
		}
	}
	if _, ok := c.AWG["HeaderProtectionKey"]; ok {
		for _, key := range []string{"S1", "S2", "S3", "S4"} {
			if number(key) < 12 {
				return awg("awg_header_protection_requires_padding", "header protection requires S1-S4 of at least 12", key).Arg("min", "12")
			}
		}
	}
	// A full transport message must still fit one UDP datagram.
	// The engine caps content padding by the UDP window, so only S4 and the
	// MTU bound a transport message.
	if number("S4")+messageSizes["S4"]+uint64(c.TunnelMTU()) > maxDatagram {
		return awg("number_out_of_range", "S4 with the tunnel MTU exceeds a UDP datagram", "S4").Also("MTU").Arg("min", "0").Arg("max", strconv.Itoa(maxDatagram-int(messageSizes["S4"])-c.TunnelMTU()))
	}
	hasV6 := false
	for _, a := range c.Addresses {
		hasV6 = hasV6 || a.Addr().Is6()
	}
	if hasV6 && c.MTU != 0 && c.MTU < 1280 {
		return problem.New("number_out_of_range", "IPv6 tunnel addresses require MTU of at least 1280").In(Interface).At("MTU").Arg("min", "1280").Arg("max", "9000")
	}
	return nil
}

func reservedWithAWG() *problem.Error {
	return problem.New("wireguard_reserved_unsupported", "Nonzero WireGuard Reserved is only supported for plain WireGuard").In(Peer).At("Reserved")
}
