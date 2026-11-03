package routing

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func bytesField(n protowire.Number, b []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, n, protowire.BytesType), b)
}
func intField(n protowire.Number, v uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, n, protowire.VarintType), v)
}
func message(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}
func geoGroup(id string, entries ...[]byte) []byte {
	b := bytesField(1, []byte(id))
	for _, e := range entries {
		b = append(b, bytesField(2, e)...)
	}
	return bytesField(1, b)
}
func geoCIDR(ip string, bits uint64) []byte {
	return message(bytesField(1, netip.MustParseAddr(ip).AsSlice()), intField(2, bits))
}
func geoDomain(typ uint64, value string) []byte {
	return message(intField(1, typ), bytesField(2, []byte(value)))
}
func fixture() ([]byte, []byte) {
	ips := message(geoGroup("ZZ", geoCIDR("203.0.113.99", 24), geoCIDR("2001:db8::", 32)), geoGroup("local", geoCIDR("10.0.0.0", 8)))
	sites := geoGroup("Sites", geoDomain(0, "needle"), geoDomain(1, `^rx[0-9]+\.example$`), geoDomain(2, "Root.Example"), geoDomain(3, "full.example"))
	return ips, sites
}
func mustGeo(t testing.TB) *GeoData {
	t.Helper()
	a, b := fixture()
	d, err := DecodeGeoData(a, b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func TestGeoDataPolicy(t *testing.T) {
	d := mustGeo(t)
	for _, kind := range []string{"GeoIP", "geosite"} {
		names, err := d.Groups(kind)
		if err != nil || len(names) == 0 {
			t.Fatal(names, err)
		}
		names[0] = "mutated"
		again, _ := d.Groups(kind)
		if again[0] == "mutated" {
			t.Fatal("group names alias dataset")
		}
	}
	names, _ := d.Groups("GEOIP")
	if !reflect.DeepEqual(names, []string{"local", "zz"}) {
		t.Fatal(names)
	}
	if _, err := d.Groups("bad"); err == nil {
		t.Fatal("invalid kind accepted")
	}
	c := Config{Default: Direct, Rules: []Rule{{GeoSite: " Sites ", Action: Proxy}, {GeoIP: "ZZ, local", Action: Block}, {Domain: "later.example", Action: Proxy}, {CIDR: "0.0.0.0/0", Action: Direct}}}
	p, err := CompileWithGeoData(c, d)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip, domain string
		want       Action
	}{
		{"203.0.113.1", "www.root.example", Proxy}, {"203.0.113.1", "later.example", Block},
		{"2001:db8::1", "", Block}, {"::ffff:203.0.113.1", "", Block}, {"10.1.1.1", "", Block},
		{"1.1.1.1", "abcNEEDLExyz", Proxy}, {"1.1.1.1", "rx12.example", Proxy},
		{"1.1.1.1", "FULL.EXAMPLE.", Proxy}, {"1.1.1.1", "sub.full.example", Direct},
		{"1.1.1.1", "badroot.example", Direct},
	}
	for _, tc := range cases {
		if got := p.Decide(netip.MustParseAddr(tc.ip), tc.domain); got != tc.want {
			t.Errorf("%+v: %s", tc, got)
		}
	}
	for _, s := range []string{"root.example", "www.root.example.", "rx12.example", "xneedlex", "full.example"} {
		if !p.DomainRelevant(s) {
			t.Error("irrelevant", s)
		}
	}
	if p.DomainRelevant("sub.full.example") || p.DomainRelevant("") {
		t.Fatal("false relevance")
	}
	if got := p.Decide(netip.Addr{}, "root.example"); got != Proxy {
		t.Fatal("SOCKS domain", got)
	}
	if got := p.Decide(netip.Addr{}, ""); got != Direct {
		t.Fatal("unknown IP matched", got)
	}
	for _, domains := range [][]string{{"unrelated", "root.example"}, {"root.example", "unrelated"}} {
		if p.DecideDomains(netip.MustParseAddr("203.0.113.1"), domains) != Proxy {
			t.Fatal("domain order changed rule order")
		}
	}
	if len(p.DirectPrefixes()) != 0 {
		t.Fatal("geo rule bypassed")
	}
	if !reflect.DeepEqual(c, p.Config()) {
		t.Fatalf("roundtrip: %#v", p.Config())
	}
	raw, err := json.Marshal(p.Config())
	if err != nil {
		t.Fatal(err)
	}
	var round Config
	if err = json.Unmarshal(raw, &round); err != nil {
		t.Fatal(err)
	}
	if _, err = CompileWithGeoData(round, d); err != nil {
		t.Fatal(err)
	}
	// Decoder must not retain caller-owned bytes.
	a, b := fixture()
	snapshot, err := DecodeGeoData(a, b)
	if err != nil {
		t.Fatal(err)
	}
	clear(a)
	clear(b)
	if !snapshot.ips["zz"].matches(netip.MustParseAddr("203.0.113.1")) || !snapshot.sites["sites"].matches("root.example") {
		t.Fatal("input mutation altered snapshot")
	}
}
func TestGeoReverseAndDefaults(t *testing.T) {
	group := message(bytesField(1, []byte("reverse")), bytesField(2, geoCIDR("203.0.113.0", 24)), intField(3, 1))
	d, err := DecodeGeoData(bytesField(1, group), nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := CompileWithGeoData(Config{Default: Direct, Rules: []Rule{{GeoIP: "reverse", Action: Block}}}, d)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip   netip.Addr
		want Action
	}{{netip.MustParseAddr("203.0.113.1"), Direct}, {netip.MustParseAddr("1.1.1.1"), Block}, {netip.MustParseAddr("::1"), Block}, {netip.Addr{}, Direct}} {
		if p.Decide(tc.ip, "") != tc.want {
			t.Fatal(tc)
		}
	}
	// An omitted prefix is protobuf's valid /0 default; omitted domain type is Plain.
	d, err = DecodeGeoData(geoGroup("all", bytesField(1, []byte{0, 0, 0, 0})), geoGroup("plain", bytesField(2, []byte("needle"))))
	if err != nil {
		t.Fatal(err)
	}
	if !d.ips["all"].matches(netip.MustParseAddr("1.2.3.4")) || !d.sites["plain"].matches("xneedlex") {
		t.Fatal("proto3 defaults")
	}
	// Attributes: key bytes, bool varint, signed int64 represented as varint.
	attrs := message(bytesField(3, message(bytesField(1, []byte("flag")), intField(2, 1))), bytesField(3, message(bytesField(1, []byte("number")), intField(3, ^uint64(0)))))
	_, err = DecodeGeoData(nil, geoGroup("attrs", message(geoDomain(3, "example.com"), attrs)))
	if err != nil {
		t.Fatal(err)
	}
}
func TestGeoRuleErrors(t *testing.T) {
	d := mustGeo(t)
	for _, tc := range []struct {
		r           Rule
		data        *GeoData
		code, group string
	}{
		{Rule{GeoIP: "zz", Action: Block}, nil, "geodata_required", ""},
		{Rule{GeoSite: "sites", Action: Block}, &GeoData{}, "geodata_required", ""},
		{Rule{GeoIP: "unknown", Action: Block}, d, "geodata_group_unknown", "unknown"},
		{Rule{GeoIP: "zz,", Action: Block}, d, "geodata_identifier_invalid", ""},
		{Rule{GeoSite: "sites,,sites", Action: Block}, d, "geodata_identifier_invalid", ""},
		{Rule{GeoSite: "sites@secret", Action: Block}, d, "geodata_identifier_invalid", ""},
	} {
		_, err := CompileWithGeoData(Config{Default: Direct, Rules: []Rule{{Domain: "earlier", Action: Direct}, tc.r}}, tc.data)
		var ge *GeoDataError
		if !errors.As(err, &ge) || ge.Code != tc.code || ge.Rule != 2 || ge.Group != tc.group {
			t.Fatalf("%+v: %v", tc, err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatal("unsafe error")
		}
	}
	for _, r := range []Rule{{GeoIP: "zz", GeoSite: "sites", Action: Block}, {GeoIP: "zz", Domain: "example", Action: Block}, {GeoSite: "sites", CIDR: "0.0.0.0/0", Action: Block}, {Action: Block}} {
		if _, err := CompileWithGeoData(Config{Default: Direct, Rules: []Rule{r}}, d); err == nil {
			t.Fatal("invalid rule accepted")
		}
	}
	if _, err := Compile(Config{Default: Direct, Rules: []Rule{{GeoIP: "zz", Action: Block}}}); err == nil {
		t.Fatal("Compile accepted geo without dataset")
	}
}
func TestGeoMalformed(t *testing.T) {
	for name, b := range map[string][]byte{
		"tag": {0}, "truncated": {10, 4, 1}, "overflow": {8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1},
		"group": {11, 12}, "wrong top wire": intField(1, 1), "missing id": bytesField(1, nil),
		"invalid id": geoGroup("secret/value"), "duplicate": message(geoGroup("ZZ"), geoGroup("zz")),
		"bad address":     geoGroup("zz", bytesField(1, []byte{1, 2, 3})),
		"bad prefix":      geoGroup("zz", geoCIDR("1.1.1.1", 33)),
		"bad reverse":     bytesField(1, message(bytesField(1, []byte("zz")), intField(3, 2))),
		"wrong cidr wire": geoGroup("zz", intField(1, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeGeoData(b, nil)
			var ge *GeoDataError
			if !errors.As(err, &ge) || ge.Kind != "geoip" || ge.Code == "" {
				t.Fatalf("accepted or untyped: %v", err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("unsafe error")
			}
		})
	}
	for name, b := range map[string][]byte{
		"enum": geoGroup("sites", geoDomain(4, "example")), "regex": geoGroup("sites", geoDomain(1, "SECRET[")),
		"empty": geoGroup("sites", geoDomain(3, "")), "utf8": geoGroup("sites", geoDomain(0, string([]byte{255}))),
		"domain":            geoGroup("sites", geoDomain(2, ".")),
		"attribute wire":    geoGroup("sites", message(geoDomain(3, "example"), bytesField(3, bytesField(2, []byte("x"))))),
		"attribute framing": geoGroup("sites", message(geoDomain(3, "example"), bytesField(3, []byte{0}))),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeGeoData(nil, b)
			var ge *GeoDataError
			if !errors.As(err, &ge) || ge.Kind != "geosite" {
				t.Fatalf("accepted or untyped: %v", err)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("regex leaked")
			}
		})
	}
	// Valid unknown fields of supported wire types remain forward compatible.
	unknown := message(intField(20, 7), bytesField(21, []byte("ignored")), protowire.AppendFixed32(protowire.AppendTag(nil, 22, protowire.Fixed32Type), 7), protowire.AppendFixed64(protowire.AppendTag(nil, 23, protowire.Fixed64Type), 7))
	if _, err := DecodeGeoData(message(geoGroup("zz"), unknown), nil); err != nil {
		t.Fatal(err)
	}
}
func TestGeoLimits(t *testing.T) {
	cases := []struct {
		name     string
		ip, site []byte
	}{
		{"bytes", make([]byte, maxGeoBytes+1), nil},
	}
	var groups []byte
	for i := 0; i <= maxGeoGroups; i++ {
		groups = append(groups, geoGroup(fmt.Sprintf("g%d", i))...)
	}
	cases = append(cases, struct {
		name     string
		ip, site []byte
	}{"groups", groups, nil})
	var patterns [][]byte
	for i := 0; i <= maxGeoRegex; i++ {
		patterns = append(patterns, geoDomain(1, "x"))
	}
	cases = append(cases, struct {
		name     string
		ip, site []byte
	}{"regex count", nil, geoGroup("regex", patterns...)})
	patterns = nil
	for i := 0; i <= maxGeoRegexBytes/maxGeoString; i++ {
		patterns = append(patterns, geoDomain(1, strings.Repeat("x", maxGeoString)))
	}
	cases = append(cases, struct {
		name     string
		ip, site []byte
	}{"regex bytes", nil, geoGroup("regex", patterns...)})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeGeoData(tc.ip, tc.site)
			var ge *GeoDataError
			if !errors.As(err, &ge) || ge.Code != "geodata_limit" {
				t.Fatal(err)
			}
		})
	}
}
func TestGeoDirectPrefixes(t *testing.T) {
	d := mustGeo(t)
	for _, earlier := range []Rule{{GeoIP: "zz", Action: Block}, {GeoSite: "sites", Action: Proxy}} {
		p, err := CompileWithGeoData(Config{Default: Proxy, Rules: []Rule{{CIDR: "192.168.0.0/16", Action: Direct}, earlier, {CIDR: "10.0.0.0/8", Action: Direct}}}, d)
		if err != nil {
			t.Fatal(err)
		}
		got := p.DirectPrefixes()
		if len(got) != 1 || got[0].String() != "192.168.0.0/16" {
			t.Fatal(got)
		}
	}
}
func FuzzDecodeGeoData(f *testing.F) {
	a, b := fixture()
	f.Add(a, b)
	f.Add([]byte{0}, []byte{10, 255})
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, a, b []byte) {
		if len(a)+len(b) > 1<<20 {
			t.Skip()
		}
		d, err := DecodeGeoData(a, b)
		if err == nil {
			_, _ = d.Groups("GeoIP")
			_, _ = d.Groups("GeoSite")
		}
	})
}
func BenchmarkDecodeGeoData(b *testing.B) {
	var ip, site [][]byte
	for i := 0; i < 10000; i++ {
		ip = append(ip, geoCIDR(fmt.Sprintf("10.%d.%d.0", i/256, i%256), 24))
		site = append(site, geoDomain(2, fmt.Sprintf("site%d.example", i)))
	}
	a, c := geoGroup("ips", ip...), geoGroup("sites", site...)
	b.ReportAllocs()
	b.SetBytes(int64(len(a) + len(c)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := DecodeGeoData(a, c); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkGeoDecide(b *testing.B) {
	var entries [][]byte
	for i := 0; i < 10000; i++ {
		entries = append(entries, geoDomain(2, fmt.Sprintf("site%d.example", i)))
	}
	a, _ := fixture()
	d, err := DecodeGeoData(a, geoGroup("sites", entries...))
	if err != nil {
		b.Fatal(err)
	}
	p, err := CompileWithGeoData(Config{Default: Direct, Rules: []Rule{{GeoSite: "sites", Action: Proxy}, {GeoIP: "zz", Action: Block}}}, d)
	if err != nil {
		b.Fatal(err)
	}
	for _, s := range []string{"www.site9999.example", "miss.example"} {
		b.Run(s, func(b *testing.B) {
			ip := netip.MustParseAddr("203.0.113.1")
			b.ReportAllocs()
			for b.Loop() {
				p.Decide(ip, s)
			}
		})
	}
}

func TestGeoErrorJSON(t *testing.T) {
	e := &GeoDataError{Code: "geodata_invalid", Kind: "GeoSite", Group: "sites", Rule: 2, Err: errors.New("private cause")}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"code":"geodata_invalid","kind":"GeoSite","group":"sites","rule":2}` {
		t.Fatal(string(b))
	}
	var round GeoDataError
	if err = json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	if round.Error() == "" {
		t.Fatal("empty error")
	}
	if !errors.Is(e, e.Err) {
		t.Fatal("cause not unwrapped")
	}
	for _, input := range [][]byte{nil, {}, intField(20, 1)} {
		d, err := DecodeGeoData(input, input)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range []Rule{{GeoIP: "zz", Action: Block}, {GeoSite: "sites", Action: Block}} {
			_, err = CompileWithGeoData(Config{Default: Direct, Rules: []Rule{r}}, d)
			var ge *GeoDataError
			if !errors.As(err, &ge) || ge.Code != "geodata_required" {
				t.Fatal(err)
			}
		}
	}
}

func TestGeoDataLiteralBangIdentifier(t *testing.T) {
	d, err := DecodeGeoData(nil, geoGroup("CATEGORY-GAMES-!CN", geoDomain(2, "games.example")))
	if err != nil {
		t.Fatal(err)
	}
	names, err := d.Groups("geosite")
	if err != nil || !reflect.DeepEqual(names, []string{"category-games-!cn"}) {
		t.Fatal(names, err)
	}
	p, err := CompileWithGeoData(Config{Default: Direct, Rules: []Rule{{GeoSite: "CATEGORY-GAMES-!CN", Action: Proxy}}}, d)
	if err != nil {
		t.Fatal(err)
	}
	if p.Decide(netip.Addr{}, "games.example") != Proxy || p.Decide(netip.Addr{}, "other.example") != Direct {
		t.Fatal("bang changed literal matching")
	}
	for _, id := range []string{"", "sites@cn", "a\x01b", "é", "K", strings.Repeat("a", 257)} {
		if _, err := DecodeGeoData(nil, geoGroup(id, geoDomain(2, "games.example"))); err == nil {
			t.Fatalf("decoded %q", id)
		}
		if _, err := CompileWithGeoData(Config{Default: Direct, Rules: []Rule{{GeoSite: id, Action: Proxy}}}, d); err == nil {
			t.Fatalf("compiled %q", id)
		}
	}
}
