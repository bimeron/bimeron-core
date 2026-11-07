package routing

import (
	"errors"
	"strings"
	"testing"

	"bimeron/internal/problem"
)

func TestCompileProblems(t *testing.T) {
	earlier := Rule{CIDR: "10.0.0.0/8, 192.168.0.0/16", Action: Direct}
	for _, tc := range []struct {
		name          string
		c             Config
		code, message string
		section       string
		field         string
		related       string
		rule          int
		allowed       string
	}{
		{"default", Config{Default: "drop"}, "choice_invalid", "invalid default action", "Routing", "Default", "", 0, "direct, proxy, block"},
		{"no matcher", Config{Default: Direct, Rules: []Rule{earlier, {Action: Proxy}}}, "rule_matcher_count", "invalid rule 2", "Rule", "", "", 2, ""},
		{"two matchers", Config{Default: Direct, Rules: []Rule{earlier, {Domain: "example.com", GeoIP: "zz", Action: Proxy}}}, "rule_matcher_count", "invalid rule 2", "Rule", "Domain", "GeoIP", 2, ""},
		{"missing action", Config{Default: Direct, Rules: []Rule{earlier, {Domain: "example.com"}}}, "value_required", "invalid rule 2", "Rule", "Action", "", 2, ""},
		{"bad action", Config{Default: Direct, Rules: []Rule{earlier, {Domain: "example.com", Action: "drop"}}}, "choice_invalid", "invalid rule 2", "Rule", "Action", "", 2, "direct, proxy, block"},
		{"cidr", Config{Default: Direct, Rules: []Rule{earlier, {CIDR: "10.0.0.0/8, 10.0.0.0/33", Action: Proxy}}}, "cidr_invalid", "invalid CIDR in rule 2", "Rule", "CIDR", "", 2, ""},
		{"domain", Config{Default: Direct, Rules: []Rule{earlier, {Domain: "*.example.com", Action: Proxy}}}, "domain_invalid", "invalid domain in rule 2", "Rule", "Domain", "", 2, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(tc.c)
			p, ok := problem.As(err)
			if !ok || err.Error() != tc.message {
				t.Fatalf("error = %v", err)
			}
			if p.Code != tc.code || p.Section != tc.section || p.Field != tc.field || strings.Join(p.Related, ",") != tc.related || p.Rule != tc.rule || p.Args["allowed"] != tc.allowed {
				t.Fatalf("problem = %+v", p)
			}
			if !problem.Known(p.Code) {
				t.Fatalf("code %q has no catalog entry", p.Code)
			}
		})
	}
}

func TestGeoDataErrorProblem(t *testing.T) {
	d := mustGeo(t)
	_, err := CompileWithGeoData(Config{Default: Direct, Rules: []Rule{{CIDR: "10.0.0.0/8", Action: Direct}, {GeoSite: "sites, Unknown", Action: Block}}}, d)
	p, ok := problem.As(err)
	if !ok || p.Code != "geodata_group_unknown" || p.Section != "Rule" || p.Field != "GeoSite" || p.Rule != 2 || p.Args["group"] != "unknown" || p.Message != err.Error() {
		t.Fatalf("rule problem = %+v (%v)", p, err)
	}
	var ge *GeoDataError
	if !errors.As(p, &ge) || ge.Code != "geodata_group_unknown" {
		t.Fatal("problem does not keep the GeoDataError for existing callers")
	}

	_, err = DecodeGeoData(nil, []byte{0})
	p, ok = problem.As(err)
	if !ok || p.Code != "geodata_invalid" || p.Section != "GeoData" || p.Field != "GeoSiteFile" || p.Rule != 0 || p.Args != nil {
		t.Fatalf("dataset problem = %+v (%v)", p, err)
	}

	for _, tc := range []struct {
		err          *GeoDataError
		section      string
		field, group string
		rule         int
	}{
		{&GeoDataError{Code: "geodata_required", Kind: "geoip"}, "GeoData", "GeoIPFile", "", 0},
		{&GeoDataError{Code: "geodata_limit", Kind: "GeoSite"}, "GeoData", "GeoSiteFile", "", 0},
		{&GeoDataError{Code: "geodata_identifier_invalid", Kind: "geoip", Rule: 3}, "Rule", "GeoIP", "", 3},
		{&GeoDataError{Code: "geodata_invalid", Kind: "geosite", Group: "sites"}, "GeoData", "GeoSiteFile", "sites", 0},
		{&GeoDataError{Code: "geodata_invalid"}, "GeoData", "", "", 0},
	} {
		p := problem.Of(tc.err)
		if p.Code != tc.err.Code || p.Section != tc.section || p.Field != tc.field || p.Args["group"] != tc.group || p.Rule != tc.rule || p.Message != tc.err.Error() {
			t.Errorf("%+v: problem = %+v", tc.err, p)
		}
		if !problem.Known(p.Code) {
			t.Errorf("code %q has no catalog entry", p.Code)
		}
	}
}
