package core

import (
	"strings"
	"testing"

	"bimeron/internal/problem"
)

// TestConvertAccessPreservesDocument changes only [AccessKey] source lines; the
// BOM, CRLF, comments, other options and sections keep their bytes.
func TestConvertAccessPreservesDocument(t *testing.T) {
	const head = "\ufeff# header comment\r\n[Profile]\r\nVersion = 1\r\nName = Kept\r\n\r\n[AccessKey]\r\n# access comment\r\n"
	const tail = "IdentityFile = ~/.ssh/id_ed25519\r\n\r\n[Rule]\r\nGeoIP = ru\r\nAction = direct\r\n# [Rule]\r\n# Domain = example.org\r\n# Action = block\r\n"
	original := head + "SSH = ssh://alice@example.com:2222\r\n" + tail
	d := ParseConfigDocument([]byte(original))
	if err := d.ConvertAccess(true); err != nil {
		t.Fatal(err)
	}
	fields := string(d.Bytes())
	want := head + "Type = ssh\r\nServer = example.com\r\nPort = 2222\r\nUsername = alice\r\n" + tail
	if fields != want {
		t.Fatalf("fields:\n%q\nwant:\n%q", fields, want)
	}
	if d.RuleCount() != 2 {
		t.Fatalf("rules = %d", d.RuleCount())
	}
	if err := d.ConvertAccess(false); err != nil {
		t.Fatal(err)
	}
	if got := string(d.Bytes()); got != head+"SSH = ssh://alice@example.com:2222\r\n"+tail {
		t.Fatalf("uri:\n%q", got)
	}
}

// TestConvertAccessQuotesValues writes values that a bare line would change
// as Go strings, and keeps a final line without a terminator unterminated.
func TestConvertAccessQuotesValues(t *testing.T) {
	d := ParseConfigDocument([]byte("[Profile]\nVersion = 1\n[AccessKey]\nTrojan = trojan://%20secret%20@example.com:443"))
	if err := d.ConvertAccess(true); err != nil {
		t.Fatal(err)
	}
	got := string(d.Bytes())
	if !strings.Contains(got, "Password = \" secret \"\n") || strings.HasSuffix(got, "\n") {
		t.Fatalf("got %q", got)
	}
	if err := d.ConvertAccess(false); err != nil {
		t.Fatal(err)
	}
	if got := string(d.Bytes()); !strings.HasPrefix(got, "[Profile]\nVersion = 1\n[AccessKey]\nTrojan = trojan://%20secret%20@example.com:443") {
		t.Fatalf("got %q", got)
	}
}

func TestConvertAccessFailuresKeepDocument(t *testing.T) {
	cases := []struct {
		name, profile, code string
		toFields            bool
	}{
		{"no-access", "[Profile]\nVersion = 1\n[IKEv2]\nWindowsProfile = Corp\n", "access_conversion_unsupported", true},
		{"ssconf", "[Profile]\nVersion = 1\n[AccessKey]\nSSConf = ssconf://example.com/key\n", "access_conversion_unsupported", true},
		{"duplicate-section", "[AccessKey]\nSS = ss://a\n[AccessKey]\nSS = ss://b\n", "section_duplicate", true},
		{"duplicate-option", "[AccessKey]\nSS = ss://a\nSS = ss://b\n", "option_duplicate", true},
		{"after-disabled-rule", "[AccessKey]\n# [Rule]\n# CIDR = 10.0.0.0/8\nSS = ss://a\n", "section_ambiguous", true},
		{"invalid", "[AccessKey]\nTrojan = trojan://SENTINEL@example.com:443?security=none\n", "choice_invalid", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := ParseConfigDocument([]byte(tc.profile))
			err := d.ConvertAccess(tc.toFields)
			if p, ok := problem.As(err); !ok || p.Code != tc.code {
				t.Fatalf("got %v, want %s", err, tc.code)
			}
			if string(d.Bytes()) != tc.profile {
				t.Fatal("failure changed the document")
			}
			if strings.Contains(err.Error(), "SENTINEL") {
				t.Fatalf("error exposes input: %v", err)
			}
		})
	}
}
