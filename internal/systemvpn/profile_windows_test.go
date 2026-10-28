//go:build windows

package systemvpn

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestProfileJournalReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	record := profileRecord{Version: 1, Name: "Owned", Server: "vpn.example.com"}
	if err := writeProfileRecord(path, record, true); err != nil {
		t.Fatal(err)
	}
	if err := writeProfileRecord(path, record, true); err == nil {
		t.Fatal("journal overwrite accepted")
	}
	record.Snapshot = "public settings"
	if err := writeProfileRecord(path, record, false); err != nil {
		t.Fatal(err)
	}
	got, err := readProfileRecord(path)
	if err != nil || *got != record {
		t.Fatal(got, err)
	}
}

// Opt-in only: creates/removes profiles under the current disposable account.
func TestWindowsIKEv2ProfilePreparation(t *testing.T) {
	server := os.Getenv("BIMERON_IKEV2_PROFILE_TEST_SERVER")
	if server == "" {
		t.Skip("requires an isolated Windows account and explicit profile-test opt-in")
	}
	cfg := Config{WindowsProfile: fmt.Sprintf("Bimeron preparation test %d", time.Now().UnixNano()), ServerName: server}
	local, _ := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	appData, _ := windows.KnownFolderPath(windows.FOLDERID_RoamingAppData, 0)
	path := filepath.Join(local, "Bimeron", "ikev2-profiles", profileKey(cfg.WindowsProfile)+".json")
	d := &windowsDriver{phonebook: filepath.Join(appData, "Microsoft", "Network", "Connections", "Pbk", "rasphone.pbk")}
	plan, err := PrepareProfile(cfg, false, false)
	if err != nil || plan.Action != "create" {
		t.Fatal(plan, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("preview wrote an ownership record", err)
	}
	if snapshot, _, err := profileSnapshot(d, cfg); err != nil || snapshot != "" {
		t.Fatal("preview created a profile", err)
	}
	plan, err = PrepareProfile(cfg, true, false)
	if err != nil || plan.Action != "created" {
		t.Fatal(plan, err)
	}
	t.Cleanup(func() {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		if _, err := PrepareProfile(cfg, false, true); err != nil {
			t.Log("explicit test-profile cleanup required:", cfg.WindowsProfile, err)
		}
	})
	if err := d.inspect(cfg); err != nil {
		t.Fatal("created profile fails native guards", err)
	}
	record, _ := os.ReadFile(path)
	plan, err = PrepareProfile(cfg, true, false)
	if err != nil || plan.Action != "unchanged" {
		t.Fatal("repeat preparation", plan, err)
	}
	after, _ := os.ReadFile(path)
	if string(record) != string(after) {
		t.Fatal("no-op changed manifest")
	}
	// Change a native setting excluded by superficial cmdlet-only snapshots.
	e, err := d.entry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	original := e
	e.RedialCount = 3
	setEntry := func(entry *rasEntry) {
		book, _ := windows.UTF16PtrFromString(d.phonebook)
		name, _ := windows.UTF16PtrFromString(cfg.WindowsProfile)
		code, _, _ := rasDLL.NewProc("RasSetEntryPropertiesW").Call(uintptr(unsafe.Pointer(book)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(entry)), unsafe.Sizeof(*entry), 0, 0)
		if code != 0 {
			t.Fatal("test mutation failed", code)
		}
	}
	setEntry(&e)
	for _, remove := range []bool{false, true} {
		if _, err := PrepareProfile(cfg, !remove, remove); err == nil {
			t.Fatal("modified profile accepted")
		}
	}
	setEntry(&original)
	// Profile-owned routes live outside RASENTRY and must also be checked.
	savedScript := profileScript
	profileScript = strings.Replace(savedScript, "switch ($config.action) {", "switch ($config.action) { 'test-add-route' { Add-VpnConnectionRoute -ConnectionName $config.name -DestinationPrefix '192.0.2.0/24' -RouteMetric 7 -ErrorAction Stop | Out-Null }; 'test-remove-route' { Remove-VpnConnectionRoute -ConnectionName $config.name -DestinationPrefix '192.0.2.0/24' -Confirm:$false -ErrorAction Stop }", 1)
	if _, err := profileOperation("test-add-route", cfg, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareProfile(cfg, true, false); err == nil {
		t.Fatal("modified routes accepted")
	}
	if _, err := profileOperation("test-remove-route", cfg, ""); err != nil {
		t.Fatal(err)
	}
	profileScript = savedScript
	plan, err = PrepareProfile(cfg, false, true)
	if err != nil || plan.Action != "removed" {
		t.Fatal("explicit remove", plan, err)
	}
	// A matching name without its ownership record must never be adopted.
	if _, err := profileOperation("create", cfg, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareProfile(cfg, true, false); err == nil {
		t.Fatal("unowned name accepted")
	}
	_, public, err := profileSnapshot(d, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profileOperation("remove", cfg, public); err != nil {
		t.Fatal(err)
	}
	// Force a failure after Add-VpnConnection to exercise partial rollback.
	profileScript = strings.Replace(profileScript, "$createdGuid = [string]$profile.Guid", "$createdGuid = [string]$profile.Guid; throw 'Injected test failure'", 1)
	_, err = PrepareProfile(cfg, true, false)
	profileScript = savedScript
	if err == nil || err.Error() != "ikev2_profile_creation_failed_rolled_back" {
		t.Fatal("rollback result", err)
	}
	if snapshot, _, err := profileSnapshot(d, cfg); err != nil || snapshot != "" {
		t.Fatal("rollback left a profile", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("rollback left a journal", err)
	}
	// A profile that appeared during a failed create is not this transaction's
	// resource. Preserve it and the pending journal for explicit manual review.
	profileScript = strings.Replace(savedScript, "if ($null -ne $profile) { throw 'Profile already exists.' }", "Add-VpnConnection -Name $config.name -ServerAddress $config.server -TunnelType Ikev2 -ErrorAction Stop | Out-Null; throw 'Injected competing creator'", 1)
	_, err = PrepareProfile(cfg, true, false)
	profileScript = savedScript
	if err == nil || err.Error() != "ikev2_profile_rollback_incomplete_manual_review_required" {
		t.Fatal("foreign resource was not preserved", err)
	}
	_, public, err = profileSnapshot(d, cfg)
	if err != nil || public == "" {
		t.Fatal("foreign profile disappeared", err)
	}
	if _, err := profileOperation("remove", cfg, public); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := writeProfileRecord(path, profileRecord{Version: 1, Name: cfg.WindowsProfile, Server: cfg.ServerName}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareProfile(cfg, true, false); err == nil {
		t.Fatal("interrupted journal accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}
