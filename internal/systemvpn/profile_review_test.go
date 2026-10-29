package systemvpn

import "testing"

func TestReviewedProfileTokenIncludesGUIDSettingsAndJournal(t *testing.T) {
	c := Config{WindowsProfile: "Corporate", ServerName: "vpn.example.com"}
	record := &profileRecord{Version: 1, Name: c.WindowsProfile, Server: c.ServerName, Snapshot: "guid-and-public-settings"}
	token := profileStateToken(c, "guid-and-public-settings", record)
	if len(token) != 64 || profileStateToken(c, "replacement-guid", record) == token {
		t.Fatal("replacement not detected")
	}
	record.Snapshot = ""
	if profileStateToken(c, "guid-and-public-settings", record) == token {
		t.Fatal("pending journal not detected")
	}
	if err := checkProfileRecord(record, c, "guid-and-public-settings"); err == nil {
		t.Fatal("interrupted transaction accepted")
	}
}
