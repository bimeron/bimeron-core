package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigDocumentRoundTrip(t *testing.T) {
	for _, text := range []string{"", "\ufeff[Profile]\r\nName = test\r\n\r\n[Future]\r\nOpaque = yes\r\n[Rule]\r\nCIDR = 10.0.0.0/8\r\nAction = direct", "# example\n# [Rule]\n# GeoSite = ads, future-group\n# # original comment\n# Action = block\n", string([]byte{0xff, 0, 10})} {
		d := ParseConfigDocument([]byte(text))
		if string(d.Bytes()) != text {
			t.Fatal("roundtrip changed bytes")
		}
		b := d.Bytes()
		if len(b) > 0 {
			b[0] = 'x'
			if string(d.Bytes()) != text {
				t.Fatal("Bytes aliases storage")
			}
		}
	}
}

func TestConfigDocumentToggle(t *testing.T) {
	original := "[Profile]\r\nName = test\r\n[Rule]\r\n  GeoIP = ru, by\r\n# original comment\r\n; another comment\r\n\r\nAction = direct\r\n[Routing]\r\nDefault = proxy\r\n"
	d := ParseConfigDocument([]byte(original))
	for n := 0; n < 3; n++ {
		if err := d.SetRuleEnabled(0, false); err != nil {
			t.Fatal(err)
		}
		disabled := string(d.Bytes())
		if !strings.Contains(disabled, "# # original comment\r\n# ; another comment") {
			t.Fatal(disabled)
		}
		reparsed := ParseConfigDocument(d.Bytes())
		r, _ := reparsed.Rule(0)
		if r == nil || r.Enabled || r.Matcher != "GeoIP" {
			t.Fatalf("disabled row: %+v", r)
		}
		if err := d.SetRuleEnabled(0, true); err != nil {
			t.Fatal(err)
		}
		if string(d.Bytes()) != original {
			t.Fatal("toggle changed original")
		}
		if err := reparsed.SetRuleEnabled(0, true); err != nil {
			t.Fatal(err)
		}
		if string(reparsed.Bytes()) != original {
			t.Fatal("raw/table transition lost comments")
		}
	}
}

func TestConfigDocumentCandidates(t *testing.T) {
	tests := []struct {
		body  string
		valid bool
	}{
		{"CIDR = 10.0.0.0/8, ::/0\nAction = proxy", true},
		{"Domain = example.org\nAction = direct", true},
		{"GeoIP = not-installed\nAction = block", true},
		{"GeoSite = unknown@attribute, another\nAction = block", true},
		{"GeoIP = ru,,by\nAction = direct", false},
		{"CIDR = nope\nAction = direct", false},
		{"Domain = a\nGeoIP = ru\nAction = direct", false},
		{"Domain = a\nDomain = b\nAction = direct", false},
		{"Domain = a\nAction = direct\nAction = block", false},
		{"GeoSite = ads", false},
		{"Action = direct", false},
		{"Domain = a\nAction = invalid", false},
		{"Domain = a\nbroken\nAction = direct", false},
	}
	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			text := "# [Rule]\n# " + strings.ReplaceAll(tt.body, "\n", "\n# ") + "\n[Profile]\nName = x\n"
			d := ParseConfigDocument([]byte(text))
			want := 0
			if tt.valid {
				want = 1
			}
			if d.RuleCount() != want {
				t.Fatalf("got %d rows", d.RuleCount())
			}
			if string(d.Bytes()) != text {
				t.Fatal("candidate changed")
			}
		})
	}
}

func TestConfigDocumentUnknownAndInvalid(t *testing.T) {
	text := "[Future]\nX = y\n[Rule]\nDomain = example.org\nFuture = keep me\nAction = direct\n# [Rule]\n# GeoSite = ads\n# Future = preserve\n# Action = block\n[Rule]\nDomain = a\nCIDR = ::/0\nAction = direct\n"
	d := ParseConfigDocument([]byte(text))
	if d.RuleCount() != 3 {
		t.Fatal(d.RuleCount())
	}
	for i := 0; i < 3; i++ {
		r, _ := d.Rule(i)
		if r.Editable || r.Error == "" {
			t.Fatalf("unsafe row %+v", r)
		}
		if d.SetRule(i, "Domain", "new.org", "block") == nil {
			t.Fatal("edited unsafe row")
		}
	}
	if d.SetRuleEnabled(1, true) == nil {
		t.Fatal("enabled unknown fields")
	}
	if string(d.Bytes()) != text {
		t.Fatal("failed mutation changed document")
	}
	if err := d.SetRuleEnabled(0, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(d.Bytes()), "# Future = keep me") {
		t.Fatal("unknown field lost")
	}
}

func TestConfigDocumentEdit(t *testing.T) {
	for _, prefix := range []string{"", "# "} {
		text := prefix + "[Rule]\r\n" + prefix + " \tDomain \t=  example.org \t\r\n" + prefix + "# keep\r\n" + prefix + "Action=direct\r\n"
		d := ParseConfigDocument([]byte(text))
		if err := d.SetRule(0, "GeoSite", "github, youtube", "proxy"); err != nil {
			t.Fatal(err)
		}
		expected := strings.ReplaceAll(strings.ReplaceAll(text, "Domain \t=  example.org", "GeoSite \t=  github, youtube"), "Action=direct", "Action=proxy")
		if string(d.Bytes()) != expected {
			t.Fatalf("got %q want %q", d.Bytes(), expected)
		}
		for _, args := range [][3]string{{"Enabled", "yes", "direct"}, {"Domain", "a\nAction=block", "direct"}, {"GeoIP", "ru,", "direct"}, {"Domain", "a", "DIRECT"}, {"Domain", " a", "direct"}} {
			if err := d.SetRule(0, args[0], args[1], args[2]); err == nil {
				t.Fatal("accepted invalid edit")
			}
			if string(d.Bytes()) != expected {
				t.Fatal("failed edit changed bytes")
			}
		}
	}
}

func TestConfigDocumentMove(t *testing.T) {
	a := "[Rule]\nDomain = first.org\n# first comment\nAction = direct\n"
	b := "# [Rule]\n# GeoSite = ads\n# # inner\n# Action = block\n"
	c := "[Rule]\nCIDR = ::/0\nAction = proxy\n"
	d := ParseConfigDocument([]byte("[Routing]\nDefault = direct\n" + a + b + c))
	if err := d.MoveRule(0, 2); err != nil {
		t.Fatal(err)
	}
	if string(d.Bytes()) != "[Routing]\nDefault = direct\n"+b+c+a {
		t.Fatal(string(d.Bytes()))
	}
	if err := d.MoveRule(2, 0); err != nil {
		t.Fatal(err)
	}
	if string(d.Bytes()) != "[Routing]\nDefault = direct\n"+a+b+c {
		t.Fatal("move back changed bytes")
	}
	if d.MoveRule(-1, 0) == nil || d.MoveRule(0, 3) == nil {
		t.Fatal("accepted invalid index")
	}
	d = ParseConfigDocument([]byte(a + strings.TrimSuffix(b, "\n")))
	if err := d.MoveRule(1, 0); err != nil {
		t.Fatal(err)
	}
	if got := string(d.Bytes()); got != b+strings.TrimSuffix(a, "\n") {
		t.Fatalf("newline seam: %q", got)
	}
	r, _ := d.Rule(0)
	if r.Enabled {
		t.Fatal("move enabled disabled row")
	}
}

func TestConfigDocumentJSON(t *testing.T) {
	d := ParseConfigDocument([]byte("# [Rule]\n# GeoIP = ru\n# Action = direct\n"))
	s, err := d.RulesJSON()
	if err != nil {
		t.Fatal(err)
	}
	var rows []ConfigDocumentRule
	if err := json.Unmarshal([]byte(s), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Enabled || rows[0].Value != "ru" {
		t.Fatal(s)
	}
	if _, err := d.Rule(1); err == nil {
		t.Fatal("accepted invalid index")
	}
}

func TestConfigDocumentWhitespaceAndBOM(t *testing.T) {
	text := "\ufeff  # [Rule]\r\n\t# GeoIP = ru\r\n  # # inner comment\r\n  # Action = direct\r\n"
	d := ParseConfigDocument([]byte(text))
	if d.RuleCount() != 1 {
		t.Fatal(d.RuleCount())
	}
	if err := d.SetRuleEnabled(0, true); err != nil {
		t.Fatal(err)
	}
	expected := "\ufeff  [Rule]\r\n\tGeoIP = ru\r\n  # inner comment\r\n  Action = direct\r\n"
	if string(d.Bytes()) != expected {
		t.Fatalf("got %q", d.Bytes())
	}
	if err := d.SetRuleEnabled(0, false); err != nil {
		t.Fatal(err)
	}
	if string(d.Bytes()) != text {
		t.Fatal("lost original outer whitespace")
	}
	d = ParseConfigDocument([]byte("\ufeff[Rule]\nDomain = a\nAction = direct\n[Rule]\nDomain = b\nAction = block\n"))
	if err := d.MoveRule(0, 1); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(d.Bytes()), "\ufeff[Rule]\nDomain = b") {
		t.Fatal("BOM moved with row")
	}
	if err := d.SetRuleEnabled(0, false); err != nil {
		t.Fatal(err)
	}
	if ParseConfigDocument(d.Bytes()).RuleCount() != 2 {
		t.Fatal("BOM toggle lost row")
	}
}

func TestConfigDocumentMoveUnknown(t *testing.T) {
	a := "[Rule]\nDomain = a\nFuture = opaque\nAction = direct\n"
	middle := "[Future]\nValue = untouched\n"
	b := "# [Rule]\n# CIDR = ::/0\n# Action = block\n"
	d := ParseConfigDocument([]byte(a + middle + b))
	if err := d.MoveRule(0, 1); err != nil {
		t.Fatal(err)
	}
	if string(d.Bytes()) != middle+b+a {
		t.Fatal(string(d.Bytes()))
	}
	if err := d.MoveRule(1, 0); err != nil {
		t.Fatal(err)
	}
	if string(d.Bytes()) != middle+a+b {
		t.Fatal(string(d.Bytes()))
	}
	r, _ := d.Rule(0)
	r.Value = "mutated snapshot"
	actual, _ := d.Rule(0)
	if actual.Value != "a" {
		t.Fatal("row aliases document")
	}
	before := string(d.Bytes())
	if d.SetRuleEnabled(9, true) == nil || d.SetRule(9, "Domain", "a", "direct") == nil {
		t.Fatal("invalid index accepted")
	}
	if string(d.Bytes()) != before {
		t.Fatal("failed operation changed bytes")
	}
	s, err := ParseConfigDocument(nil).RulesJSON()
	if err != nil || s != "[]" {
		t.Fatalf("empty JSON %q %v", s, err)
	}
}

func TestConfigDocumentQuotedValues(t *testing.T) {
	for _, prefix := range []string{"", "# "} {
		for _, tt := range []struct{ matcher, encoded, value string }{
			{"Domain", `"ex\x61mple.org"`, "example.org"},
			{"CIDR", `"10.0.0.0/8, ::/0"`, "10.0.0.0/8, ::/0"},
			{"GeoSite", `"ads, tracking"`, "ads, tracking"},
		} {
			text := prefix + "[Rule]\r\n" + prefix + tt.matcher + " = " + tt.encoded + "\r\n" + prefix + `Action = "\x64irect"` + "\r\n"
			d := ParseConfigDocument([]byte(text))
			r, err := d.Rule(0)
			if err != nil || !r.Editable || r.Value != tt.value || r.Action != "direct" {
				t.Fatalf("quoted row: %+v, %v", r, err)
			}
			if string(d.Bytes()) != text {
				t.Fatal("parsing changed quoted bytes")
			}
			if err := d.SetRule(0, r.Matcher, r.Value, r.Action); err != nil {
				t.Fatal(err)
			}
			r, err = ParseConfigDocument(d.Bytes()).Rule(0)
			if err != nil || !r.Editable || r.Value != tt.value || r.Action != "direct" {
				t.Fatalf("edited quoted row: %+v, %v", r, err)
			}
		}
	}
	// A semantic value starting with a quote must be escaped on write, or the
	// runtime will interpret the value as an encoded string (or reject it).
	d := ParseConfigDocument([]byte("[Rule]\nDomain = example.org\nAction = direct\n"))
	value := `"example.org`
	if err := d.SetRule(0, "Domain", value, "proxy"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(d.Bytes()), `Domain = "\"example.org"`) {
		t.Fatalf("unescaped semantic quote: %s", d.Bytes())
	}
	r, err := ParseConfigDocument(d.Bytes()).Rule(0)
	if err != nil || !r.Editable || r.Value != value {
		t.Fatalf("semantic quote lost: %+v, %v", r, err)
	}
}

func TestConfigDocumentRejectQuotedNewlines(t *testing.T) {
	for _, value := range []string{`"10.0.0.0/8\n"`, `"10.0.0.0/8\r"`, `"unterminated`} {
		text := "[Rule]\nCIDR = " + value + "\nAction = direct\n"
		d := ParseConfigDocument([]byte(text))
		r, _ := d.Rule(0)
		if r.Editable || d.SetRule(0, "CIDR", "::/0", "block") == nil {
			t.Fatalf("accepted unsafe quoted row: %+v", r)
		}
		if string(d.Bytes()) != text {
			t.Fatal("rejected edit changed bytes")
		}
	}
	d := ParseConfigDocument([]byte("[Rule]\nCIDR = ::/0\nAction = direct\n"))
	before := string(d.Bytes())
	for _, value := range []string{"::/0\n", "::/0\r", "::/0\n[Rule]\nDomain=evil"} {
		if d.SetRule(0, "CIDR", value, "direct") == nil || string(d.Bytes()) != before {
			t.Fatal("newline edit was not rejected atomically")
		}
	}
}

func TestConfigDocumentMovePreservesUnknownEOF(t *testing.T) {
	for _, eol := range []string{"\n", "\r\n"} {
		for _, tail := range []string{"[Future]", "[Future]" + eol + "Opaque = keep", "[Future]" + eol + "Opaque = keep\r"} {
			a := strings.ReplaceAll("[Rule]\nDomain = a\nAction = direct\n", "\n", eol)
			b := strings.ReplaceAll("[Rule]\nDomain = b\nAction = block\n", "\n", eol)
			d := ParseConfigDocument([]byte(a + b + tail))
			if err := d.MoveRule(0, 1); err != nil {
				t.Fatal(err)
			}
			if got := string(d.Bytes()); got != b+a+tail {
				t.Fatalf("unknown EOF changed: got %q want %q", got, b+a+tail)
			}
		}
	}
}
