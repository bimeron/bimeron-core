package core

import (
	"strings"
	"testing"

	"bimeron/internal/config"
	"bimeron/internal/problem"
	"bimeron/internal/routing"
)

// wantProblem checks the code, message and location of a returned problem.
type wantProblem struct {
	code, message, section, field string
	rule                          int
}

func checkProblem(t *testing.T, name string, err error, want wantProblem) {
	t.Helper()
	p, ok := problem.As(err)
	if !ok {
		t.Errorf("%s: uncoded error %v", name, err)
		return
	}
	if p.Code != want.code || p.Message != want.message || err.Error() != want.message || p.Section != want.section || p.Field != want.field || p.Rule != want.rule {
		t.Errorf("%s: problem = %+v, want %+v", name, p, want)
	}
	if !problem.Known(p.Code) {
		t.Errorf("%s: code %q has no catalog entry", name, p.Code)
	}
}

func TestConfigDocumentProblems(t *testing.T) {
	// Rows: 0 active ([Rule] 1), 1 disabled, 2 active ([Rule] 2).
	const text = "[Rule]\nDomain=a.test\nAction=direct\n# [Rule]\n# Domain=b.test\n# Action=block\n[Rule]\nDomain=c.test\nAction=proxy\n"
	d := ParseConfigDocument([]byte(text))
	for name, tc := range map[string]struct {
		err  error
		want wantProblem
	}{
		"out of range":   {d.SetRule(3, "Domain", "x.test", "direct"), wantProblem{"rule_index_out_of_range", "rule index out of range", "Rule", "", 0}},
		"insert range":   {d.InsertRule(4, "Domain", "x.test", "direct", true), wantProblem{"rule_index_out_of_range", "rule index out of range", "Rule", "", 0}},
		"delete range":   {d.DeleteRule(-1), wantProblem{"rule_index_out_of_range", "rule index out of range", "Rule", "", 0}},
		"domain":         {d.SetRule(2, "Domain", "a b", "direct"), wantProblem{"domain_invalid", "invalid domain", "Rule", "Domain", 2}},
		"root dots":      {d.SetRule(2, "Domain", "..", "direct"), wantProblem{"domain_invalid", "invalid domain", "Rule", "Domain", 2}},
		"disabled cidr":  {d.SetRule(1, "CIDR", "10.0.0.0/33", "direct"), wantProblem{"cidr_invalid", "invalid CIDR", "Rule", "CIDR", 0}},
		"empty cidr":     {d.SetRule(0, "CIDR", "", "direct"), wantProblem{"value_required", "invalid CIDR", "Rule", "CIDR", 1}},
		"geodata":        {d.SetRule(0, "GeoIP", "ru,", "direct"), wantProblem{"geodata_identifier_invalid", "invalid geodata identifier", "Rule", "GeoIP", 1}},
		"matcher":        {d.SetRule(0, "Enabled", "yes", "direct"), wantProblem{"choice_invalid", "invalid matcher", "Rule", "", 1}},
		"action":         {d.SetRule(0, "Domain", "a.test", "DIRECT"), wantProblem{"choice_invalid", "invalid rule action", "Rule", "Action", 1}},
		"missing action": {d.SetRule(2, "Domain", "a.test", ""), wantProblem{"value_required", "invalid rule action", "Rule", "Action", 2}},
		"spaces":         {d.SetRule(0, "Domain", " a.test", "direct"), wantProblem{"value_has_invalid_characters", "invalid rule value", "Rule", "Domain", 1}},
		"action newline": {d.SetRule(0, "Domain", "a.test", "direct\n"), wantProblem{"value_has_invalid_characters", "invalid rule value", "Rule", "Action", 1}},
		"insert value":   {d.InsertRule(0, "Domain", "a\nAction=block", "direct", true), wantProblem{"value_has_invalid_characters", "invalid rule value", "Rule", "Domain", 0}},
	} {
		checkProblem(t, name, tc.err, tc.want)
	}
	if string(d.Bytes()) != text {
		t.Fatal("failed operations changed the document")
	}

	// Rows: 0 active with an unknown field, 1 disabled with an unknown field,
	// 2 active with two matchers.
	blocked := ParseConfigDocument([]byte("[Rule]\nDomain = example.org\nFuture = keep me\nAction = direct\n# [Rule]\n# GeoSite = ads\n# Future = preserve\n# Action = block\n[Rule]\nDomain = a\nCIDR = ::/0\nAction = direct\n[Rule]\nDomain = a\nDomain = b\nAction = direct\n"))
	checkProblem(t, "unknown field", blocked.SetRule(0, "Domain", "new.org", "block"), wantProblem{"option_unknown", `cannot edit rule: unknown rule field "Future"; use raw editing`, "Rule", "", 1})
	checkProblem(t, "enable unknown", blocked.SetRuleEnabled(1, true), wantProblem{"option_unknown", `cannot enable rule: unknown rule field "Future"; use raw editing`, "Rule", "", 0})
	checkProblem(t, "two matchers", blocked.SetRule(2, "Domain", "new.org", "block"), wantProblem{"rule_matcher_count", "cannot edit rule: rule requires exactly one matcher", "Rule", "Domain", 2})
	checkProblem(t, "duplicate field", blocked.SetRule(3, "Domain", "new.org", "block"), wantProblem{"option_duplicate", "cannot edit rule: malformed or duplicate rule field", "Rule", "Domain", 3})
	if r, _ := blocked.Rule(2); r.Error != "rule requires exactly one matcher" || r.Editable {
		t.Fatalf("row = %+v", r)
	}
	if p, _ := problem.As(blocked.SetRule(2, "Domain", "new.org", "block")); strings.Join(p.Related, ",") != "CIDR" {
		t.Fatalf("related = %v", p.Related)
	}
}

func TestConfigDocumentSectionProblems(t *testing.T) {
	d := ParseConfigDocument([]byte("[Routing]\nDefault=direct\n"))
	checkProblem(t, "value", d.SetSectionField("Routing", "Default", "a\nb"), wantProblem{"value_has_invalid_characters", "invalid section field", "Routing", "Default", 0})
	checkProblem(t, "rule section", d.SetSectionField("Rule", "Domain", "a"), wantProblem{"value_invalid", "invalid section field", "", "", 0})
	checkProblem(t, "duplicate section", ParseConfigDocument([]byte("[Routing]\nDefault=direct\n[Routing]\nDefault=proxy\n")).SetSectionField("Routing", "Default", "block"), wantProblem{"section_duplicate", "duplicate section", "Routing", "", 0})
	checkProblem(t, "duplicate key", ParseConfigDocument([]byte("[Routing]\nDefault=direct\nDefault=proxy\n")).SetSectionField("Routing", "Default", "block"), wantProblem{"option_duplicate", "malformed or duplicate section field", "Routing", "Default", 0})
	checkProblem(t, "ambiguous", ParseConfigDocument([]byte("[Routing]\n# [Rule]\n# Domain=a\n# Action=block\nDefault=direct\n")).SetSectionField("Routing", "Default", "proxy"), wantProblem{"section_ambiguous", "ambiguous section fields after disabled rule; use raw editing", "Routing", "Default", 0})
	for text, want := range map[string]wantProblem{
		"[Profile]\nName=one\nName=two\n":            {"option_duplicate", "duplicate section field", "Profile", "Name", 0},
		"[Profile]\nName=one\n[Profile]\nName=two\n": {"section_duplicate", "duplicate section", "Profile", "", 0},
		"[Profile]\nName=\"broken\n":                 {"syntax_invalid", "invalid quoted section field", "Profile", "Name", 0},
		"[Profile]\nbroken\n":                        {"syntax_invalid", "malformed section field", "Profile", "", 0},
		"Name=orphan\n":                              {"syntax_invalid", "malformed section field", "", "", 0},
	} {
		_, err := ParseConfigDocument([]byte(text)).FieldsJSON()
		checkProblem(t, text, err, want)
	}
}

func TestSessionConfigProblems(t *testing.T) {
	domain, err := routing.Compile(routing.Config{Default: routing.Proxy, Rules: []routing.Rule{{CIDR: "10.0.0.0/8, 172.16.0.0/12", Action: routing.Direct}, {Domain: "example.org", Action: routing.Direct}}})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		change func(*SessionConfig)
		want   wantProblem
	}{
		"resolver":      {func(c *SessionConfig) { c.Resolve = nil }, wantProblem{"access_key_missing", "missing access key resolver", "AccessKey", "", 0}},
		"mode":          {func(c *SessionConfig) { c.Mode = "tap" }, wantProblem{"choice_invalid", "mode must be vpn or proxy", "Interface", "Mode", 0}},
		"proxy kill":    {func(c *SessionConfig) { c.Mode, c.KillSwitch = "proxy", true }, wantProblem{"kill_switch_requires_vpn", "KillSwitch requires VPN mode", "Interface", "KillSwitch", 0}},
		"listen":        {func(c *SessionConfig) { c.Mode, c.Listen = "proxy", "0.0.0.0:1080" }, wantProblem{"listen_invalid", "SOCKS listener must use loopback", "Interface", "Listen", 0}},
		"proxy IPv6":    {func(c *SessionConfig) { c.Mode, c.DisableIPv6 = "proxy", true }, wantProblem{"ipv6_disable_requires_vpn", "IPv6 disable requires VPN mode", "Interface", "IPv6", 0}},
		"name":          {func(c *SessionConfig) { c.Name = "1tun" }, wantProblem{"interface_name_invalid", "invalid tunnel name", "Interface", "Name", 0}},
		"MTU":           {func(c *SessionConfig) { c.MTU = 9000 }, wantProblem{"number_out_of_range", "MTU must be between 1280 and 1500", "Interface", "MTU", 0}},
		"DNS":           {func(c *SessionConfig) { c.DNS = []string{"dns.example"} }, wantProblem{"dns_invalid", "DNS must contain unicast IPv4 addresses separated by commas", "Interface", "DNS", 0}},
		"kill switch":   {func(c *SessionConfig) { c.KillSwitch, c.Policy = true, domain }, wantProblem{"kill_switch_cidr_only", "rule 3: kill switch supports CIDR rules only", "Rule", "Domain", 0}},
		"ikev2 options": {func(c *SessionConfig) { *c = ikev2TestConfig(); c.MTU = 1420 }, wantProblem{"ikev2_exclusive", "ikev2_unsupported_session_options", "IKEv2", "", 0}},
		"ikev2 server":  {func(c *SessionConfig) { *c = ikev2TestConfig(); c.IKEv2.ServerName = "vpn" }, wantProblem{"ikev2_server_name_requires_dns_name", "ikev2_server_name_requires_dns_name", "IKEv2", "ServerName", 0}},
	} {
		c := testConfig()
		tc.change(&c)
		checkProblem(t, name, c.validate(), tc.want)
	}

	c, err := config.ParseData([]byte("[Profile]\nVersion = 1\n[IKEv2]\nWindowsProfile = Corporate VPN\nServerName = vpn.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	c.Routing.Rules = []routing.Rule{{CIDR: "10.0.0.0/8", Action: routing.Direct}}
	_, err = FromConfig(c)
	checkProblem(t, "FromConfig IKEv2", err, wantProblem{"ikev2_exclusive", "invalid IKEv2 configuration", "IKEv2", "", 0})

	err = ValidateConfigDataWithGeoData([]byte("[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://aes-256-gcm:s@example.com:8388\n[Rule]\nCIDR = 10.0.0.0/8\nAction = direct\n[Rule]\nGeoSite = ads\nAction = block\n"), nil, nil)
	checkProblem(t, "geodata", err, wantProblem{"geodata_required", "geosite rule 2: dataset is unavailable", "Rule", "GeoSite", 2})
}
