package wgconf

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestImportWireGuardURI(t *testing.T) {
	q := url.Values{}
	q.Set("publickey", testKey(2))
	q.Set("presharedkey", testKey(3))
	q.Set("address", "10.0.0.2/32,fd00::2/128")
	q.Set("mtu", "1380")
	q.Set("reserved", "0,0,0")
	q.Set("keepalive", "25")
	q.Set("Jc", "4")
	q.Set("h1", "100-200")
	raw := "wireguard://" + url.QueryEscape(testKey(1)) + "@vpn.example.test:51820?" + q.Encode() + "#My%20Server"
	got, err := ImportURI(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "My Server" {
		t.Fatalf("name %q", got.Name)
	}
	c, err := Parse(got.Text)
	if err != nil {
		t.Fatalf("%v\n%s", err, got.Text)
	}
	if c.Endpoint() != "vpn.example.test:51820" || len(c.Peer.AllowedIPs) != 2 || c.MTU != 1380 || c.AWG["H1"] != "100-200" || c.AWG["Jc"] != "4" {
		t.Fatalf("config %+v", c)
	}
}

func TestImportWGHiddifyAliases(t *testing.T) {
	// '+' in an unescaped query value decodes as a space; keys are repaired.
	raw := "wg://[2001:db8::1]:443?pk=" + testKey(1) + "&peer_pk=" + strings.TrimRight(base64.URLEncoding.EncodeToString(mustKey(testKey(2))), "=") + "&local_address=10.0.0.2/32&pre_shared_key=" + testKey(3) + "#n"
	got, err := ImportURI(raw)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(got.Text)
	if err != nil {
		t.Fatalf("%v\n%s", err, got.Text)
	}
	if c.Peer.EndpointHost != "2001:db8::1" || c.Peer.PublicKey != keyOf(testKey(2)) || c.PrivateKey != keyOf(testKey(1)) {
		t.Fatal("aliases not applied")
	}
	if c.Peer.AllowedIPs[0].String() != "0.0.0.0/0" {
		t.Fatal("default AllowedIPs")
	}
}

func mustKey(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
func keyOf(s string) Key      { k, _ := parseKey(s); return k }

func TestImportURIRejections(t *testing.T) {
	base := "wireguard://" + url.QueryEscape(testKey(1)) + "@vpn.example.test:51820?publickey=" + url.QueryEscape(testKey(2)) + "&address=10.0.0.2/32"
	cases := map[string]string{
		base + "&reserved=1,2,256":     "number_invalid",
		base + "&workers=2":            "uri_option_unsupported",
		base + "&mtu=1&mtu=2":          "uri_option_unsupported",
		"wireguard://vpn.example.test": "wireguard_endpoint_invalid",
		"awg://x":                      "uri_scheme_invalid",
		"vpn://!!!":                    "vpn_uri_invalid",
		"vpn://" + amnezia(t, map[string]any{"containers": []any{map[string]any{"container": "amnezia-openvpn", "openvpn": map[string]any{}}}}): "vpn_uri_container_missing",
		"vpn://" + amnezia(t, map[string]any{"api_key": "x", "api_endpoint": "https://example.test", "description": "Free"}):                    "vpn_uri_api_key_unsupported",
	}
	for raw, want := range cases {
		_, err := ImportURI(raw)
		if code(err) != want {
			t.Errorf("%s: got %v", want, err)
		}
	}
	// A link that converts but fails validation still yields text.
	got, err := ImportURI("wireguard://" + url.QueryEscape(testKey(1)) + "@vpn.example.test:51820?address=10.0.0.2/32")
	if err != nil || got.Text == "" {
		t.Fatal("convertible link must return text")
	}
	if _, err := Parse(got.Text); code(err) != "value_required" {
		t.Fatalf("missing public key: %v", err)
	}
}

// amnezia encodes a payload the way qCompress plus base64url does.
func amnezia(t testing.TB, payload any) string {
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(len(data)))
	z := zlib.NewWriter(&b)
	_, _ = z.Write(data)
	_ = z.Close()
	return base64.RawURLEncoding.EncodeToString(b.Bytes())
}

func amneziaSample(t testing.TB, container, key string) string {
	text := strings.Replace(sample(), "DNS = 10.8.0.1, 1.1.1.1", "DNS = $PRIMARY_DNS, $SECONDARY_DNS", 1)
	if container == "amnezia-awg" {
		text = strings.Replace(text, "DNS = ", "Jc = 4\nJmin = 10\nJmax = 50\nS1 = 30\nS2 = 40\nH1 = 11\nH2 = 22\nH3 = 33\nH4 = 44\nDNS = ", 1)
	}
	last, _ := json.Marshal(map[string]any{"config": text, "hostName": "vpn.example.test", "port": 51820})
	return amnezia(t, map[string]any{
		"containers": []any{
			map[string]any{"container": "amnezia-openvpn", "openvpn": map[string]any{"last_config": "{}"}},
			map[string]any{"container": container, key: map[string]any{"last_config": string(last), "port": "51820"}},
		},
		"defaultContainer": container,
		"description":      "Amnezia server",
		"dns1":             "1.1.1.1",
		"dns2":             "1.0.0.1",
		"hostName":         "vpn.example.test",
	})
}

func TestImportAmnezia(t *testing.T) {
	for _, tc := range []struct{ container, key, protocol string }{
		{"amnezia-awg", "awg", ProtocolAmneziaWG},
		{"amnezia-wireguard", "wireguard", ProtocolWireGuard},
	} {
		got, err := ImportURI("vpn://" + amneziaSample(t, tc.container, tc.key))
		if err != nil {
			t.Fatal(err)
		}
		c, err := Parse(got.Text)
		if err != nil {
			t.Fatalf("%v\n%s", err, got.Text)
		}
		if got.Name != "Amnezia server" || c.Protocol() != tc.protocol || c.DNS[0].String() != "1.1.1.1" {
			t.Fatalf("%s: %q %s %v", tc.container, got.Name, c.Protocol(), c.DNS)
		}
	}
}

func FuzzImportURI(f *testing.F) {
	f.Add("wireguard://" + url.QueryEscape(testKey(1)) + "@h:1?publickey=" + url.QueryEscape(testKey(2)) + "&address=10.0.0.2")
	f.Add("wg://h:1?pk=a&reserved=0")
	f.Add("vpn://" + amneziaSample(f, "amnezia-awg", "awg"))
	f.Add("vpn://AAAA")
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := ImportURI(raw)
		if err != nil {
			return
		}
		if _, err := ParseDocument(got.Text); err != nil {
			t.Fatalf("import produced unparsable text: %v", err)
		}
	})
}

func FuzzParse(f *testing.F) {
	f.Add(sample())
	f.Add("[Interface]\nI1 = <b 0x01><r 5>\n[Peer]\nAllowedIPs = ::/0\n")
	f.Fuzz(func(t *testing.T, text string) {
		d, err := ParseDocument(text)
		if err != nil {
			return
		}
		if d.String() != text {
			t.Fatal("round trip changed bytes")
		}
		_ = d.Inspect()
		c, err := d.Config()
		if err == nil {
			_ = c.UAPI(netipAddrPort(), c.Peer.AllowedIPs)
		}
	})
}

func FuzzEdit(f *testing.F) {
	f.Add(sample(), "Peer", "Endpoint", "h:1")
	f.Add("", "Interface", "MTU", "")
	f.Fuzz(func(t *testing.T, text, section, key, value string) {
		d, err := ParseDocument(text)
		if err != nil {
			return
		}
		before := d.String()
		if err := d.ApplyEdits([]Edit{{section, key, value}}); err != nil {
			if d.String() != before {
				t.Fatal("failed edit changed the document")
			}
			return
		}
		fields, err := d.Fields()
		if err == nil && value != "" && fields[section+"/"+key] == "" {
			t.Fatalf("edit lost: %q", d.String())
		}
	})
}

func netipAddrPort() netip.AddrPort { return netip.MustParseAddrPort("192.0.2.1:51820") }

func TestImportThroneLink(t *testing.T) {
	hp := strings.Repeat("ab", 32)
	raw := "wg://203.0.113.10:51820?private_key=" + url.QueryEscape(testKey(1)) + "&local_address=10.8.1.2/32-fd00::2/128&enable_amnezia=true&jc=4&s1=20&s2=20&s3=20&s4=20&header_protection_key=" + hp + "&random_trailers=1&public_key=" + url.QueryEscape(testKey(2)) + "&persistent_keepalive_interval=25&reserved=0-0-0#name"
	got, err := ImportURI(raw)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(got.Text)
	if err != nil {
		t.Fatalf("%v\n%s", err, got.Text)
	}
	if len(c.Addresses) != 2 || c.AWG["RandomTrailers"] != "true" || c.AWG["HeaderProtectionKey"] == hp {
		t.Fatalf("%+v", c)
	}
	if _, err := ImportURI(strings.Replace(raw, "enable_amnezia=true", "enable_amnezia=false", 1)); code(err) != "uri_option_unsupported" {
		t.Fatal("AWG options with enable_amnezia=false must fail")
	}
}

func TestImportAmneziaVariants(t *testing.T) {
	last, _ := json.Marshal(map[string]any{"config": strings.Replace(sample(), "DNS = 10.8.0.1, 1.1.1.1", "DNS = $PRIMARY_DNS, $SECONDARY_DNS\nI2 = ", 1), "mtu": "1376", "port": 51820})
	payload := map[string]any{
		"containers": []any{
			map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": "{}"}},
			map[string]any{"container": "amnezia-awg2", "awg": map[string]any{"last_config": string(last), "protocol_version": "2"}},
		},
		"defaultContainer": "amnezia-xray", "dns1": "9.9.9.9", "dns2": "", "format_version": 1,
	}
	plain, _ := json.Marshal(payload)
	for _, link := range []string{"vpn://" + amnezia(t, payload), "vpn://" + base64.RawURLEncoding.EncodeToString(plain)} {
		got, err := ImportURI(link)
		if err != nil {
			t.Fatal(err)
		}
		c, err := Parse(got.Text)
		if err != nil {
			t.Fatalf("%v\n%s", err, got.Text)
		}
		if c.MTU != 1376 || len(c.DNS) != 1 || c.DNS[0].String() != "9.9.9.9" {
			t.Fatalf("mtu %d dns %v", c.MTU, c.DNS)
		}
	}
	payload["format_version"] = 2
	if _, err := ImportURI("vpn://" + amnezia(t, payload)); code(err) != "vpn_uri_invalid" {
		t.Fatal("newer format must be refused")
	}
	payload["format_version"] = 1
	payload["config_version"] = 2
	if _, err := ImportURI("vpn://" + amnezia(t, payload)); code(err) != "vpn_uri_api_key_unsupported" {
		t.Fatal("service keys must be refused even with containers")
	}
}

func TestAmneziaDNSCannotExpandText(t *testing.T) {
	text := strings.Replace(sample(), "DNS = 10.8.0.1, 1.1.1.1", "DNS = $PRIMARY_DNS", 1) + strings.Repeat("# $PRIMARY_DNS\n", 3000)
	last, _ := json.Marshal(map[string]any{"config": text})
	link := "vpn://" + amnezia(t, map[string]any{
		"containers": []any{map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": string(last)}}},
		"dns1":       strings.Repeat("x", 300),
	})
	got, err := ImportURI(link)
	if err == nil && len(got.Text) > MaxSize {
		t.Fatal("import exceeded the text limit")
	}
	if err == nil && strings.Contains(got.Text, "xxxx") {
		t.Fatal("a non-IP DNS value was substituted")
	}
}
