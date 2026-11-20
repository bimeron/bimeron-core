package core

import (
	"bytes"
	"testing"
)

// A draft document keeps arbitrary bytes: unchanged Bytes must reproduce the
// input exactly, toggling a rule twice must restore it, and an inserted rule
// must read back and delete.
func FuzzConfigDocument(f *testing.F) {
	for _, seed := range []string{
		"[Routing]\nDefault = proxy\n[Rule]\nCIDR = 10.0.0.0/8\nAction = direct\n#[Rule]\n#Domain = example.com\n#Action = proxy\n",
		"\ufeff[Interface]\r\nMode = vpn\r\n[AccessKey]\r\nKey = ss://YWVzLTI1Ni1nY206cHc@127.0.0.1:443\r\n",
		"[Rule]\nGeoSite = ads\nAction = block\n[Rule]\nDomain = example.com\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d := ParseConfigDocument(b)
		if !bytes.Equal(d.Bytes(), b) {
			t.Fatal("unchanged document changed its bytes")
		}
		_, _ = d.RulesJSON()
		_, _ = d.FieldsJSON()
		for i := 0; i < d.RuleCount() && i < 16; i++ {
			r, err := d.Rule(i)
			if err != nil || !r.Editable {
				continue
			}
			before := d.Bytes()
			if d.SetRuleEnabled(i, !r.Enabled) != nil {
				continue
			}
			if err := d.SetRuleEnabled(i, r.Enabled); err != nil || !bytes.Equal(d.Bytes(), before) {
				t.Fatalf("toggling rule %d twice did not restore the document: %v", i, err)
			}
		}
		n := d.RuleCount()
		if d.InsertRule(0, "Domain", "example.com", "direct", true) == nil {
			r, err := d.Rule(0)
			if d.RuleCount() != n+1 || err != nil || !r.Enabled || !r.Editable || r.Matcher != "Domain" || r.Value != "example.com" || r.Action != "direct" {
				t.Fatalf("inserted rule not found: count %d -> %d, %+v, %v", n, d.RuleCount(), r, err)
			}
			if d.DeleteRule(0) != nil || d.RuleCount() != n {
				t.Fatal("inserted rule could not be deleted")
			}
		}
		if d.RuleCount() > 1 {
			_ = d.MoveRule(0, d.RuleCount()-1)
		}
		_ = d.SetSectionField("Routing", "Default", "direct")
	})
}
