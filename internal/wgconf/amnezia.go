package wgconf

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"bimeron/internal/problem"
)

// Amnezia vpn:// links carry base64url (no padding) of a Qt qCompress
// buffer: a 4-byte big-endian uncompressed length followed by a zlib stream.
// Some exports skip compression and carry the JSON directly. The JSON lists
// protocol containers; Bimeron takes the AmneziaWG or WireGuard one, whose
// last_config is a JSON string holding the wg-quick text in "config".
// This is an independent implementation of the observed format, which its
// authors do not formally specify.

// maxAmneziaJSON bounds the decoded payload.
const maxAmneziaJSON = 1 << 20

// amneziaContainers lists accepted containers, preferred first, with the
// member holding their settings.
var amneziaContainers = []struct{ name, key string }{
	{"amnezia-awg2", "awg"},
	{"amnezia-awg", "awg"},
	{"amnezia-wireguard", "wireguard"},
}

// apiKeyFields mark Amnezia Premium/Free keys. They carry data for the
// Amnezia service API instead of a connection configuration.
var apiKeyFields = []string{"config_version", "api_config", "auth_data", "api_key", "api_endpoint"}

func amneziaInvalid() error {
	return problem.New("vpn_uri_invalid", "invalid Amnezia vpn:// link")
}

func decodeAmnezia(payload string) (map[string]json.RawMessage, error) {
	payload = strings.TrimRight(strings.TrimSpace(payload), "=")
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		if b, err = base64.RawStdEncoding.DecodeString(payload); err != nil {
			return nil, amneziaInvalid()
		}
	}
	data := inflate(b)
	if data == nil {
		// Uncompressed exports carry the JSON itself.
		data = b
	}
	var top map[string]json.RawMessage
	// The JSON decoder would silently replace invalid UTF-8.
	if len(data) > maxAmneziaJSON || !utf8.Valid(data) || json.Unmarshal(data, &top) != nil || top == nil {
		return nil, amneziaInvalid()
	}
	return top, nil
}

// inflate undoes qCompress, or returns nil when b is not such a buffer.
func inflate(b []byte) []byte {
	if len(b) < 6 {
		return nil
	}
	size := binary.BigEndian.Uint32(b[:4])
	if size == 0 || size > maxAmneziaJSON {
		return nil
	}
	z, err := zlib.NewReader(bytes.NewReader(b[4:]))
	if err != nil {
		return nil
	}
	defer z.Close()
	data, err := io.ReadAll(io.LimitReader(z, maxAmneziaJSON+1))
	if err != nil || len(data) != int(size) {
		return nil
	}
	return data
}

// jsonText reads a string or number member as text.
func jsonText(m map[string]json.RawMessage, key string) string {
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

func importAmnezia(payload string) (Imported, error) {
	top, err := decodeAmnezia(payload)
	if err != nil {
		return Imported{}, err
	}
	for _, f := range apiKeyFields {
		if _, ok := top[f]; ok {
			return Imported{}, problem.New("vpn_uri_api_key_unsupported", "Amnezia service keys are not connection configurations")
		}
	}
	if v := jsonText(top, "format_version"); v != "" {
		if n, err := strconv.Atoi(v); err != nil || n > 1 {
			return Imported{}, amneziaInvalid()
		}
	}
	missing := problem.New("vpn_uri_container_missing", "the vpn:// link has no AmneziaWG or WireGuard configuration")
	var containers []map[string]json.RawMessage
	if raw, ok := top["containers"]; !ok {
		return Imported{}, missing
	} else if err := json.Unmarshal(raw, &containers); err != nil {
		return Imported{}, amneziaInvalid()
	}
	chosen := chooseContainer(containers, jsonText(top, "defaultContainer"))
	if chosen == nil {
		return Imported{}, missing
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(chosen.object, &settings); err != nil {
		return Imported{}, amneziaInvalid()
	}
	lastText := jsonText(settings, "last_config")
	var last map[string]json.RawMessage
	if lastText == "" || json.Unmarshal([]byte(lastText), &last) != nil {
		return Imported{}, amneziaInvalid()
	}
	text := jsonText(last, "config")
	if text == "" {
		return Imported{}, amneziaInvalid()
	}
	// Bound the text before substitution, and substitute only IP addresses,
	// so placeholders cannot expand it.
	if err := checkText(text); err != nil {
		return Imported{}, err
	}
	text = strings.ReplaceAll(text, "$PRIMARY_DNS", dnsValue(top, "dns1"))
	text = strings.ReplaceAll(text, "$SECONDARY_DNS", dnsValue(top, "dns2"))
	if strings.Contains(text, "$") {
		// Placeholders that only the Amnezia client or service can fill.
		return Imported{}, amneziaInvalid()
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	d, err := ParseDocument(text)
	if err != nil {
		return Imported{}, err
	}
	// An empty dns1 or dns2 leaves an empty list item behind.
	if fields, err := d.Fields(); err == nil && fields["Interface/DNS"] != "" {
		var kept []string
		for _, item := range listItems(fields["Interface/DNS"]) {
			if item != "" {
				kept = append(kept, item)
			}
		}
		if err := d.SetField(Interface, "DNS", strings.Join(kept, ", ")); err != nil {
			return Imported{}, amneziaInvalid()
		}
	}
	// The client applies last_config's MTU when the text has none.
	if mtu := jsonText(last, "mtu"); mtu != "" {
		if fields, err := d.Fields(); err == nil && fields["Interface/MTU"] == "" {
			if err := d.SetField(Interface, "MTU", mtu); err != nil {
				return Imported{}, amneziaInvalid()
			}
		}
	}
	name := jsonText(top, "description")
	if name == "" {
		name = jsonText(top, "name")
	}
	return Imported{Text: d.String(), Name: name}, nil
}

type container struct {
	name   string
	object json.RawMessage
}

func chooseContainer(containers []map[string]json.RawMessage, preferred string) *container {
	var found []container
	for _, c := range containers {
		name := jsonText(c, "container")
		for _, accepted := range amneziaContainers {
			if name == accepted.name {
				if object, ok := c[accepted.key]; ok {
					found = append(found, container{name, object})
				}
			}
		}
	}
	for i := range found {
		if found[i].name == preferred {
			return &found[i]
		}
	}
	for _, accepted := range amneziaContainers {
		for i := range found {
			if found[i].name == accepted.name {
				return &found[i]
			}
		}
	}
	return nil
}

// dnsValue returns an Amnezia DNS member when it is a plain IP address.
func dnsValue(top map[string]json.RawMessage, key string) string {
	a, err := netip.ParseAddr(jsonText(top, key))
	if err != nil || a.Zone() != "" {
		return ""
	}
	return a.String()
}
