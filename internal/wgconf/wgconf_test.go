package wgconf

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"bimeron/internal/problem"
)

// testKey returns a deterministic generated test key, never a real one.
func testKey(b byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b + byte(i)
	}
	return base64.StdEncoding.EncodeToString(k)
}

func sample() string {
	return "[Interface]\n" +
		"PrivateKey = " + testKey(1) + "\n" +
		"Address = 10.8.0.2/32, fd00::2/128\n" +
		"DNS = 10.8.0.1, 1.1.1.1\n" +
		"\n" +
		"[Peer]\n" +
		"PublicKey = " + testKey(2) + "\n" +
		"PresharedKey = " + testKey(3) + "\n" +
		"Endpoint = vpn.example.test:51820\n" +
		"AllowedIPs = 0.0.0.0/0, ::/0\n" +
		"PersistentKeepalive = 25\n"
}

func code(err error) string {
	if err == nil {
		return ""
	}
	return problem.Of(err).Code
}

func TestParseWireGuard(t *testing.T) {
	c, err := Parse(sample())
	if err != nil {
		t.Fatal(err)
	}
	if c.Protocol() != ProtocolWireGuard || c.TunnelMTU() != DefaultMTU || c.Endpoint() != "vpn.example.test:51820" {
		t.Fatalf("unexpected config: %v %v %v", c.Protocol(), c.TunnelMTU(), c.Endpoint())
	}
	if len(c.Addresses) != 2 || len(c.DNS) != 2 || len(c.Peer.AllowedIPs) != 2 || c.Peer.Keepalive != (Range{25, 25}) {
		t.Fatalf("lists: %+v", c)
	}
	uapi := c.UAPI(netip.MustParseAddrPort("192.0.2.1:51820"), c.Peer.AllowedIPs)
	for _, want := range []string{"private_key=", "replace_peers=true\npublic_key=", "endpoint=192.0.2.1:51820\n", "persistent_keepalive_interval=25\n", "allowed_ip=0.0.0.0/0\nallowed_ip=::/0\n"} {
		if !strings.Contains(uapi, want) {
			t.Fatalf("UAPI lacks %q", want)
		}
	}
	if strings.Contains(uapi, testKey(1)) {
		t.Fatal("UAPI must use hex keys")
	}
}

func TestParseIsCaseInsensitiveAndAllowsComments(t *testing.T) {
	text := strings.ReplaceAll(sample(), "PrivateKey", "privatekey")
	text = strings.ReplaceAll(text, "[Peer]", "[peer] # comment")
	text = strings.ReplaceAll(text, "PersistentKeepalive = 25", "PersistentKeepalive = 25 # seconds")
	if _, err := Parse(text); err != nil {
		t.Fatal(err)
	}
}

func TestAWGVersions(t *testing.T) {
	cases := []struct {
		extra, version string
	}{
		{"", ""},
		{"Jc = 4\nJmin = 40\nJmax = 70\nS1 = 50\nS2 = 100\nH1 = 11\nH2 = 22\nH3 = 33\nH4 = 44\n", "1.0"},
		{"Jc = 4\nI1 = <b 0x0102><r 16><t>\n", "1.5"},
		{"S3 = 20\nS4 = 10\n", "2.0"},
		{"H1 = 100-200\nH2 = 300-400\nH3 = 500-600\nH4 = 700-800\n", "2.0"},
		{"S1 = 20\nS2 = 20\nS3 = 20\nS4 = 20\nHeaderProtectionKey = " + testKey(9) + "\n", "3.0"},
		{"RekeyAfterTime = 100-140\nMaxHandshakeAttempts = 5\n", "3.0"},
		{"RandomTrailers = true\nDisableCookies = true\n", "3.1"},
	}
	for _, tc := range cases {
		text := strings.Replace(sample(), "DNS = ", tc.extra+"DNS = ", 1)
		d, _ := ParseDocument(text)
		protocol, version := d.Protocol()
		if version != tc.version || (version == "") != (protocol == ProtocolWireGuard) {
			t.Fatalf("%q: got %s %s", tc.extra, protocol, version)
		}
		c, err := d.Config()
		if err != nil {
			t.Fatalf("%q: %v", tc.extra, err)
		}
		if tc.version != "" && c.Protocol() != ProtocolAmneziaWG {
			t.Fatal("AWG options must select amneziawg")
		}
	}
	d, _ := ParseDocument(strings.Replace(sample(), "PersistentKeepalive = 25", "PersistentKeepalive = 20-30", 1))
	if _, v := d.Protocol(); v != "3.0" {
		t.Fatalf("keepalive range version %s", v)
	}
}

func TestAWGUAPIConversion(t *testing.T) {
	text := strings.Replace(sample(), "DNS = ", "S1 = 20\nS2 = 20\nS3 = 20\nS4 = 20\nHeaderProtectionKey = "+testKey(9)+"\nH1 = 5-9\nRandomTrailers = true\nDNS = ", 1)
	c, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	uapi := c.UAPI(netip.MustParseAddrPort("192.0.2.1:1"), nil)
	k, _ := parseKey(testKey(9))
	for _, want := range []string{"s1=20\n", "h1=5-9\n", "random_trailers=true\n", "header_protection_key=" + k.hex() + "\n"} {
		if !strings.Contains(uapi, want) {
			t.Fatalf("UAPI lacks %q", want)
		}
	}
}

func TestRejections(t *testing.T) {
	replace := func(old, new string) string { return strings.Replace(sample(), old, new, 1) }
	cases := map[string]string{
		replace("[Interface]\n", "[Interface]\nPostUp = iptables -A\n"):                           "wireguard_hook_unsupported",
		replace("[Interface]\n", "[Interface]\nTable = off\n"):                                    "option_not_supported",
		replace("[Interface]\n", "[Interface]\nItime = 5\n"):                                      "option_unknown",
		replace("[Interface]\n", "[Interface]\nJ1 = <r 2>\n"):                                     "option_unknown",
		sample() + "[Peer]\nPublicKey = " + testKey(4) + "\n":                                     "wireguard_peer_count",
		strings.SplitN(sample(), "[Peer]", 2)[0]:                                                  "wireguard_peer_count",
		sample() + "[Other]\n":                                                                    "section_unknown",
		replace("[Interface]\n", "[Interface]\nnot a line\n"):                                     "syntax_invalid",
		replace("Endpoint = vpn.example.test:51820", "Endpoint = vpn.example.test"):               "wireguard_endpoint_invalid",
		replace(":51820", ":0"):                                                                   "port_invalid",
		replace("Address = 10.8.0.2/32, fd00::2/128", "Address = nope"):                           "wireguard_address_invalid",
		replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 300.0.0.0/8"):                       "wireguard_allowed_ips_invalid",
		replace("DNS = 10.8.0.1, 1.1.1.1", "DNS = 10.8.0.1, corp.example"):                        "dns_invalid",
		replace("PrivateKey = "+testKey(1), "PrivateKey = short"):                                 "wireguard_key_invalid",
		replace("PrivateKey = "+testKey(1)+"\n", ""):                                              "value_required",
		replace("PublicKey = "+testKey(2), "PublicKey = "+testKey(2)+"\nPublicKey = "+testKey(2)): "option_duplicate",
		replace("DNS = ", "Jmin = 90\nJmax = 10\nDNS = "):                                         "awg_range_invalid",
		replace("DNS = ", "Jc = 129\nDNS = "):                                                     "number_out_of_range",
		replace("DNS = ", "H1 = 2\nDNS = "):                                                       "awg_header_overlap",
		replace("DNS = ", "H1 = 9-5\nDNS = "):                                                     "awg_range_invalid",
		replace("DNS = ", "HeaderProtectionKey = "+testKey(9)+"\nDNS = "):                         "awg_header_protection_requires_padding",
		replace("DNS = ", "I1 = <x 1>\nDNS = "):                                                   "awg_tag_invalid",
		replace("DNS = ", "I1 = <b 0x0>\nDNS = "):                                                 "awg_tag_invalid",
		replace("DNS = ", "I1 = text<r 1>\nDNS = "):                                               "awg_tag_invalid",
		replace("DNS = ", "RandomTrailers = yes\nDNS = "):                                         "boolean_invalid",
		replace("DNS = ", "RekeyTimeout = 0\nDNS = "):                                             "number_out_of_range",
		replace("DNS = ", "MTU = 1000\nDNS = "):                                                   "number_out_of_range",
		replace("DNS = ", "MTU = 01420\nDNS = "):                                                  "number_invalid",
	}
	for text, want := range cases {
		_, err := Parse(text)
		if got := code(err); got != want {
			t.Errorf("want %s, got %s (%v) for:\n%s", want, got, err, text)
			continue
		}
		p := problem.Of(err)
		if p.Document != DocumentName {
			t.Errorf("%s: missing document marker", want)
		}
		for _, secret := range []string{testKey(1), testKey(2), testKey(3), testKey(9), "vpn.example.test", "corp.example"} {
			if strings.Contains(p.Message, secret) || strings.Contains(strings.Join(mapValues(p.Args), " "), secret) {
				t.Errorf("%s: problem leaks a value", want)
			}
		}
	}
}

func mapValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func TestProblemLocation(t *testing.T) {
	text := strings.Replace(sample(), "Endpoint = vpn.example.test:51820", "Endpoint = bad", 1)
	_, err := Parse(text)
	p := problem.Of(err)
	if p.Section != Peer || p.Field != "Endpoint" || p.Line != 9 {
		t.Fatalf("location %+v", p)
	}
}

func TestSizeAndEncoding(t *testing.T) {
	if code(func() error { _, err := Parse(strings.Repeat("#", MaxSize+1)); return err }()) != "file_too_large" {
		t.Fatal("size limit")
	}
	if code(func() error { _, err := Parse("[Interface]\n\xff\n"); return err }()) != "file_not_utf8" {
		t.Fatal("encoding")
	}
}

func TestCoverage(t *testing.T) {
	prefixes := func(values ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, v := range values {
			out = append(out, netip.MustParsePrefix(v))
		}
		return out
	}
	cases := []struct {
		in       []netip.Prefix
		v4, v6   string
		coverage string
	}{
		{prefixes("0.0.0.0/0", "::/0"), CoverageFull, CoverageFull, CoverageFull},
		{prefixes("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"), CoverageFull, CoverageFull, CoverageFull},
		{prefixes("0.0.0.0/0"), CoverageFull, CoverageNone, CoverageIPv4Only},
		{prefixes("0.0.0.0/0", "2000::/3"), CoverageFull, CoveragePartial, CoverageIPv4Only},
		{prefixes("10.0.0.0/8"), CoveragePartial, CoverageNone, CoveragePartial},
		{prefixes("0.0.0.0/1", "128.0.0.0/2"), CoveragePartial, CoverageNone, CoveragePartial},
		{nil, CoverageNone, CoverageNone, CoveragePartial},
	}
	for _, tc := range cases {
		s := Summarize(tc.in)
		if s.IPv4 != tc.v4 || s.IPv6 != tc.v6 || s.Coverage != tc.coverage {
			t.Errorf("%v: %+v", tc.in, s)
		}
	}
}

func TestDetect(t *testing.T) {
	cases := map[string]string{
		sample(): FormatWireGuard,
		"[Profile]\nVersion = 1\n[AccessKey]\nFile = a.conf\n": FormatBimeron,
		"[Interface]\nMode = vpn\n":                            "document_format_unknown",
		"[Profile]\nVersion = 1\n[Peer]\nPublicKey = x\n":      "document_format_ambiguous",
		"hello": "document_format_unknown",
		"[Interface]\nPrivateKey = x\n[Routing]\nDefault = proxy\n": "document_format_ambiguous",
	}
	for text, want := range cases {
		format, err := Detect(text)
		if got := format + code(err); got != want {
			t.Errorf("%q: got %s", text, got)
		}
	}
}

func TestEditPreservesBytes(t *testing.T) {
	original := bom + "# head\r\n[Interface] # c\r\nPrivateKey=" + testKey(1) + "   # keep\r\nAddress = 10.0.0.2/32\r\nAddress = fd00::2/128\r\n\r\n[Peer]\r\nPublicKey = " + testKey(2) + "\r\nUnknown = 1\r\n"
	d, err := ParseDocument(original)
	if err != nil || d.String() != original {
		t.Fatal("round trip")
	}
	if err := d.ApplyEdits([]Edit{
		{Interface, "PrivateKey", testKey(5)},
		{Interface, "Address", "10.0.0.3/32"},
		{Interface, "MTU", "1380"},
		{Peer, "Endpoint", "[2001:db8::1]:443"},
		{Peer, "PresharedKey", ""},
	}); err != nil {
		t.Fatal(err)
	}
	want := bom + "# head\r\n[Interface] # c\r\nPrivateKey=" + testKey(5) + "   # keep\r\nAddress = 10.0.0.3/32\r\nMTU = 1380\r\n\r\n[Peer]\r\nPublicKey = " + testKey(2) + "\r\nUnknown = 1\r\nEndpoint = [2001:db8::1]:443\r\n"
	if d.String() != want {
		t.Fatalf("got\n%q\nwant\n%q", d.String(), want)
	}
	if err := d.ApplyEdits([]Edit{{Interface, "MTU", ""}, {Peer, "Bogus", "1"}}); code(err) != "option_unknown" {
		t.Fatalf("unknown key edit: %v", err)
	}
	if d.String() != want {
		t.Fatal("failed batch must not change the document")
	}
	for _, bad := range []string{"a#b", " a", "a\nb"} {
		if err := d.SetField(Interface, "MTU", bad); code(err) != "value_has_invalid_characters" {
			t.Fatalf("value %q accepted", bad)
		}
	}
	if err := d.SetField(Interface, "mtu", "1"); code(err) != "option_unknown" {
		t.Fatal("edit keys must use canonical spelling")
	}
}

func TestEditFromScratchOrdersSections(t *testing.T) {
	d, _ := ParseDocument("")
	err := d.ApplyEdits([]Edit{
		{Peer, "PublicKey", testKey(2)},
		{Peer, "Endpoint", "192.0.2.1:51820"},
		{Peer, "AllowedIPs", "0.0.0.0/0"},
		{Interface, "PrivateKey", testKey(1)},
		{Interface, "Address", "10.0.0.2/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(d.String(), "[Interface]\nPrivateKey = ") || strings.Index(d.String(), "[Peer]") < strings.Index(d.String(), "Address") {
		t.Fatalf("order:\n%s", d.String())
	}
	if _, err := d.Config(); err != nil {
		t.Fatal(err)
	}
	fields, err := d.Fields()
	if err != nil || fields["Peer/Endpoint"] != "192.0.2.1:51820" {
		t.Fatalf("fields %v %v", fields, err)
	}
}

func TestFieldsJoinLists(t *testing.T) {
	d, _ := ParseDocument(sample() + "AllowedIPs = 10.0.0.0/8\n")
	fields, err := d.Fields()
	if err != nil || fields["Peer/AllowedIPs"] != "0.0.0.0/0, ::/0, 10.0.0.0/8" {
		t.Fatalf("%v %v", fields, err)
	}
	d, _ = ParseDocument(sample() + "[Peer]\n")
	if _, err := d.Fields(); code(err) != "wireguard_peer_count" {
		t.Fatal("two peers must be ambiguous")
	}
	i := d.Inspect()
	if i.FieldsError == "" || len(i.Problems) != 1 {
		t.Fatalf("inspect %+v", i)
	}
}

func TestReviewRegressions(t *testing.T) {
	replace := func(old, new string) string { return strings.Replace(sample(), old, new, 1) }
	zero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cases := map[string]string{
		replace("PrivateKey = "+testKey(1), "PrivateKey = "+zero): "wireguard_key_invalid",
		replace("PublicKey = "+testKey(2), "PublicKey = "+zero):   "wireguard_key_invalid",
		replace("DNS = ", "S1 = 65359\nDNS = "):                   "",
		replace("DNS = ", "S1 = 65360\nDNS = "):                   "number_out_of_range",
		replace("DNS = ", "S4 = 64055\nDNS = "):                   "",
		replace("DNS = ", "S4 = 64056\nDNS = "):                   "number_out_of_range",
		replace("DNS = ", "I1 = <dz 2><d>\nDNS = "):               "",
		replace("DNS = ", "I1 = <dz>\nDNS = "):                    "awg_tag_invalid",
		replace("DNS = ", "I1 = <b 0102>\nDNS = "):                "",
	}
	for text, want := range cases {
		if _, err := Parse(text); code(err) != want {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	c, err := Parse(replace("PersistentKeepalive = 25", "PersistentKeepalive = 20-30"))
	d, _ := ParseDocument(replace("PersistentKeepalive = 25", "PersistentKeepalive = 20-30"))
	if protocol, _ := d.Protocol(); err != nil || c.Protocol() != protocol || protocol != ProtocolAmneziaWG {
		t.Fatal("Config and Document must classify the protocol alike")
	}
}

func TestUnknownEditKeyNotEchoed(t *testing.T) {
	d, _ := ParseDocument(sample())
	err := d.SetField(Interface, testKey(7), "1")
	p := problem.Of(err)
	if p.Code != "option_unknown" || p.Field != "" {
		t.Fatalf("problem %+v", p)
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), testKey(7)) {
		t.Fatal("problem echoes the caller's key")
	}
}

func TestEditInspectionMatchesText(t *testing.T) {
	d, _ := ParseDocument(strings.Replace(sample(), "DNS = ", "MTU = 1420\nDNS = ", 1))
	if err := d.SetField(Interface, "MTU", "1300"); err != nil {
		t.Fatal(err)
	}
	fresh, _ := ParseDocument(d.String())
	got, want := d.Inspect(), fresh.Inspect()
	if got.Fields["Interface/MTU"] != "1300" || want.Fields["Interface/MTU"] != "1300" {
		t.Fatalf("stale fields: %v", got.Fields["Interface/MTU"])
	}
}

func TestReplaceKeepsSurroundingBytes(t *testing.T) {
	for in, want := range map[string]string{
		"MTU = 1420  \n":      "MTU = 1300  \n",
		"MTU=1420#c\r\n":      "MTU=1300#c\r\n",
		"MTU = 1420 # keep\n": "MTU = 1300 # keep\n",
		"MTU =\t1420\t#x\r\n": "MTU =\t1300\t#x\r\n",
	} {
		if got := replaceValue(in, "1300"); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestEditBatchLimit(t *testing.T) {
	d, _ := ParseDocument(sample())
	edits := make([]Edit, MaxEdits+1)
	for i := range edits {
		edits[i] = Edit{Interface, "MTU", ""}
	}
	if err := d.ApplyEdits(edits); code(err) != "invalid_request" {
		t.Fatalf("batch limit: %v", err)
	}
}
