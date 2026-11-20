package wgconf

import (
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"bimeron/internal/problem"
)

// Imported is WireGuard text built from a share link plus a suggested name.
type Imported struct {
	Text string
	Name string
}

// maxURI bounds share links; it matches the bridge text limit.
const maxURI = MaxSize

// ImportURI converts vpn://, wireguard:// and wg:// links to wg-quick text.
// Problems never contain the link or its values.
func ImportURI(raw string) (Imported, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > maxURI {
		return Imported{}, problem.New("value_too_long", "share link exceeds size limit").Arg("max", "65536")
	}
	scheme, rest, found := strings.Cut(raw, "://")
	if !found {
		scheme = ""
	}
	switch strings.ToLower(scheme) {
	case "vpn":
		return importAmnezia(rest)
	case "wireguard", "wg":
		return importWireGuardURI(raw)
	}
	return Imported{}, problem.New("uri_scheme_invalid", "share link must start with vpn://, wireguard:// or wg://").Arg("schemes", "vpn://, wireguard://, wg://")
}

// uriAliases maps normalized query names (lowercase, without '_' and '-')
// to WireGuard text fields. The names cover v2rayN/v2rayNG, Hiddify and
// Throne/NekoRay links.
var uriAliases = map[string]string{
	"privatekey": "Interface/PrivateKey", "secretkey": "Interface/PrivateKey", "pk": "Interface/PrivateKey",
	"publickey": "Peer/PublicKey", "peerpublickey": "Peer/PublicKey", "pub": "Peer/PublicKey", "peerpub": "Peer/PublicKey", "peerpk": "Peer/PublicKey",
	"presharedkey": "Peer/PresharedKey", "psk": "Peer/PresharedKey",
	"address": "Interface/Address", "ip": "Interface/Address", "localaddress": "Interface/Address",
	"mtu": "Interface/MTU", "dns": "Interface/DNS",
	"allowedips": "Peer/AllowedIPs",
	"keepalive":  "Peer/PersistentKeepalive", "persistentkeepalive": "Peer/PersistentKeepalive", "persistentkeepaliveinterval": "Peer/PersistentKeepalive",
}

func init() {
	for _, key := range AWGKeys {
		uriAliases[strings.ToLower(key)] = "Interface/" + key
	}
}

// normalizeName lowercases a query name and drops '_' and '-'.
func normalizeName(name string) string {
	return strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(name))
}

// keyFields hold base64 keys, which query decoding may have damaged.
var keyFields = map[string]bool{"Interface/PrivateKey": true, "Peer/PublicKey": true, "Peer/PresharedKey": true, "Interface/HeaderProtectionKey": true}

// repairKey restores '+' turned into spaces and converts base64url or 64
// hexadecimal digits to standard base64. It applies to every key field.
func repairKey(value string) string {
	value = strings.ReplaceAll(value, " ", "+")
	if len(value) == 64 {
		if b, err := hex.DecodeString(value); err == nil {
			return base64.StdEncoding.EncodeToString(b)
		}
	}
	if strings.ContainsAny(value, "-_") || len(value)%4 != 0 {
		trimmed := strings.TrimRight(value, "=")
		if b, err := base64.RawURLEncoding.DecodeString(strings.NewReplacer("+", "-", "/", "_").Replace(trimmed)); err == nil {
			return base64.StdEncoding.EncodeToString(b)
		}
	}
	return value
}

// uriBool canonicalizes link booleans.
func uriBool(value string) (string, bool) {
	switch strings.ToLower(value) {
	case "true", "1", "on", "yes":
		return "true", true
	case "false", "0", "off", "no":
		return "false", true
	}
	return "", false
}

func importWireGuardURI(raw string) (Imported, error) {
	invalid := func() error { return problem.New("uri_invalid", "invalid WireGuard share link") }
	unsupported := func() error {
		return problem.New("uri_option_unsupported", "unsupported or duplicate WireGuard share link option")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return Imported{}, invalid()
	}
	host, port := u.Hostname(), u.Port()
	if !utf8.ValidString(host) || !utf8.ValidString(u.Fragment) {
		return Imported{}, invalid()
	}
	if host == "" || port == "" {
		return Imported{}, problem.New("wireguard_endpoint_invalid", "WireGuard Endpoint must be host:port")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Imported{}, invalid()
	}
	fields := map[string]string{"Peer/Endpoint": net.JoinHostPort(host, port)}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			return Imported{}, problem.New("uri_credentials_invalid", "WireGuard share link must carry only the private key before @")
		}
		if !utf8.ValidString(u.User.Username()) {
			return Imported{}, invalid()
		}
		fields["Interface/PrivateKey"] = u.User.Username()
	}
	amnezia := ""
	seen := map[string]bool{}
	for name, values := range q {
		normalized := normalizeName(name)
		if len(values) != 1 || seen[normalized] {
			return Imported{}, unsupported()
		}
		seen[normalized] = true
		value := strings.TrimSpace(values[0])
		if !utf8.ValidString(value) {
			return Imported{}, invalid()
		}
		switch normalized {
		case "reserved":
			if !zeroReserved(value) {
				return Imported{}, problem.New("wireguard_reserved_unsupported", "WireGuard reserved bytes are not supported")
			}
			continue
		case "enableamnezia":
			if amnezia, _ = uriBool(value); amnezia == "" {
				return Imported{}, unsupported()
			}
			continue
		}
		field, ok := uriAliases[normalized]
		if !ok {
			return Imported{}, unsupported()
		}
		if _, dup := fields[field]; dup {
			return Imported{}, unsupported()
		}
		switch field {
		case "Interface/Address":
			// Throne joins several addresses with '-'.
			value = strings.ReplaceAll(value, "-", ",")
		case "Interface/RandomTrailers", "Interface/DisableCookies":
			if b, ok := uriBool(value); ok {
				value = b
			}
		}
		if keyFields[field] {
			value = repairKey(value)
		}
		if _, list := listKeys[strings.SplitN(field, "/", 2)[1]]; list {
			value = strings.Join(listItems(value), ", ")
		}
		fields[field] = value
	}
	if amnezia == "false" {
		for field := range fields {
			if slices.Contains(AWGKeys, strings.TrimPrefix(field, "Interface/")) {
				return Imported{}, unsupported()
			}
		}
	}
	if _, ok := fields["Peer/AllowedIPs"]; !ok {
		fields["Peer/AllowedIPs"] = "0.0.0.0/0, ::/0"
	}
	text, err := Build(fields)
	if err != nil {
		return Imported{}, err
	}
	return Imported{Text: text, Name: u.Fragment}, nil
}

// zeroReserved accepts an absent reserved field: decimal bytes separated by
// ',' or '-', or base64, all zero.
func zeroReserved(value string) bool {
	if value == "" {
		return true
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '-' })
	decimal := len(parts) > 0
	for _, part := range parts {
		if n, err := strconv.Atoi(strings.TrimSpace(part)); err != nil || n != 0 {
			decimal = false
			break
		}
	}
	if decimal {
		return true
	}
	b, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(b) > 0 && !slices.ContainsFunc(b, func(c byte) bool { return c != 0 })
}

// canonicalOrder is the key order of generated text.
var canonicalOrder = func() []string {
	out := []string{"Interface/PrivateKey", "Interface/Address", "Interface/DNS", "Interface/MTU", "Interface/ListenPort"}
	for _, k := range AWGKeys {
		out = append(out, "Interface/"+k)
	}
	return append(out, "Peer/PublicKey", "Peer/PresharedKey", "Peer/Endpoint", "Peer/AllowedIPs", "Peer/PersistentKeepalive")
}()

// Build renders fields as canonical wg-quick text. Empty values are omitted.
// Unknown fields fail. The result is not validated.
func Build(fields map[string]string) (string, error) {
	for field := range fields {
		section, key, _ := strings.Cut(field, "/")
		if canonical, ok := canonicalKey(section, key); !ok || canonical != key || (section != Interface && section != Peer) {
			return "", problem.New("option_unknown", "unknown WireGuard option").InDocument(DocumentName)
		}
	}
	d, _ := ParseDocument("")
	for _, field := range canonicalOrder {
		value := fields[field]
		if value == "" {
			continue
		}
		section, key, _ := strings.Cut(field, "/")
		if err := d.SetField(section, key, value); err != nil {
			return "", err
		}
	}
	return d.String(), nil
}
