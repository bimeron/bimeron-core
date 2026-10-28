package systemvpn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileOwnershipRefusesConflicts(t *testing.T) {
	cfg := Config{WindowsProfile: "Owned VPN", ServerName: "vpn.example.com"}
	for _, tc := range []struct {
		name      string
		record    *profileRecord
		snapshot  string
		wantError bool
	}{
		{"new", nil, "", false},
		{"collision", nil, "foreign", true},
		{"matching", &profileRecord{1, cfg.WindowsProfile, cfg.ServerName, "settings"}, "settings", false},
		{"modified", &profileRecord{1, cfg.WindowsProfile, cfg.ServerName, "settings"}, "modified", true},
		{"missing", &profileRecord{1, cfg.WindowsProfile, cfg.ServerName, "settings"}, "", true},
		{"interrupted", &profileRecord{1, cfg.WindowsProfile, cfg.ServerName, ""}, "", true},
		{"replacement", &profileRecord{1, "Other", cfg.ServerName, "settings"}, "settings", true},
		{"server change", &profileRecord{1, cfg.WindowsProfile, "other.example.com", "settings"}, "settings", true},
		{"version", &profileRecord{2, cfg.WindowsProfile, cfg.ServerName, "settings"}, "settings", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkProfileRecord(tc.record, cfg, tc.snapshot); (err != nil) != tc.wantError {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
	if profileKey("Owned VPN") != profileKey("owned vpn") {
		t.Fatal("case variants have separate ownership records")
	}
}

func TestCorruptProfileRecordIsNotOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	if record, err := readProfileRecord(path); record != nil || err != nil {
		t.Fatal(record, err)
	}
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProfileRecord(path); err == nil {
		t.Fatal("corrupt manifest accepted")
	}
}

func TestProfilePreparationRejectsWildcardNames(t *testing.T) {
	for _, name := range []string{"VPN*", "VPN?", "VPN`*"} {
		if err := validatePreparationConfig(Config{WindowsProfile: name, ServerName: "vpn.example.com"}); err == nil {
			t.Fatal("accepted wildcard name", name)
		}
	}
}
