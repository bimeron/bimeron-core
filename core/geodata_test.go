package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bimeron/internal/routing"
)

func geoField(n byte, b []byte) []byte {
	out := []byte{n<<3 | 2}
	out = binary.AppendUvarint(out, uint64(len(b)))
	return append(out, b...)
}
func geoFixtures() ([]byte, []byte) {
	cidr := append(geoField(1, []byte{203, 0, 113, 0}), 16, 24)
	ip := geoField(1, append(geoField(1, []byte("ZZ")), geoField(2, cidr)...))
	domain := append([]byte{8, 2}, geoField(2, []byte("example.org"))...)
	site := geoField(1, append(geoField(1, []byte("TEST")), geoField(2, domain)...))
	return ip, site
}

const geoProfile = "[Profile]\nVersion = 1\n[AccessKey]\nKey = ss://aes-256-gcm:secret@127.0.0.1:8388\n[GeoData]\nGeoIPFile = data/geoip.dat\nGeoSiteFile = data/geosite.dat\n"
const geoRules = "[Rule]\nGeoSite = test\nAction = block\n[Rule]\nGeoIP = zz\nAction = direct\n"

func TestGeoDataExplicitResourcesAndFileSnapshot(t *testing.T) {
	ip, site := geoFixtures()
	profile := []byte(geoProfile + geoRules)
	if _, err := LoadConfigData(profile); err == nil {
		t.Fatal("byte loader accepted missing resources")
	}
	cfg, err := LoadConfigDataWithGeoData(profile, ip, site)
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("203.0.113.9")
	if cfg.Policy.Decide(addr, "example.org") != routing.Block || cfg.Policy.Decide(addr, "") != routing.Direct {
		t.Fatal("mixed routing order")
	}
	// Decoding owns the data; a host may reuse its byte buffers immediately.
	clear(ip)
	clear(site)
	if cfg.Policy.Decide(addr, "www.example.org") != routing.Block {
		t.Fatal("caller mutation changed policy")
	}
	ip, site = geoFixtures()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"profile.conf": profile, "data/geoip.dat": ip, "data/geosite.dat": site} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "profile.conf")
	// Even readable absolute references cannot cause the bytes-only API to open resources.
	absoluteProfile := bytes.ReplaceAll(profile, []byte("data/geoip.dat"), []byte(filepath.ToSlash(filepath.Join(dir, "data/geoip.dat"))))
	absoluteProfile = bytes.ReplaceAll(absoluteProfile, []byte("data/geosite.dat"), []byte(filepath.ToSlash(filepath.Join(dir, "data/geosite.dat"))))
	if _, err := LoadConfigData(absoluteProfile); err == nil {
		t.Fatal("bytes-only loader read existing absolute dataset paths")
	}
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ProfileID == "" {
		t.Fatal("missing profile identity")
	}
	if err := os.WriteFile(filepath.Join(dir, "data/geosite.dat"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if loaded.Policy.Decide(addr, "example.org") != routing.Block {
		t.Fatal("replacement changed session snapshot")
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("next load ignored replacement")
	}
}

func TestGeoDataValidationAndDiscovery(t *testing.T) {
	ip, site := geoFixtures()
	for kind, data := range map[string][]byte{"geoip": ip, "geosite": site} {
		groups, err := GeoDataGroups(kind, data)
		if err != nil || len(groups) != 1 {
			t.Fatalf("groups %s: %v %v", kind, groups, err)
		}
	}
	if _, err := GeoDataGroups("other", ip); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if err := ValidateConfigDataWithGeoData([]byte(geoProfile+geoRules), ip, site); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{
		"[Rule]\nGeoIP = unknown\nAction = direct\n",
		"[Rule]\nGeoSite = test,\nAction = direct\n",
		"[Interface]\nKillSwitch = true\n" + geoRules,
		"[Interface]\nKillSwitch = true\n[Rule]\nDomain = example.org\nAction = direct\n",
	} {
		if _, err := LoadConfigDataWithGeoData([]byte(geoProfile+extra), ip, site); err == nil {
			t.Fatalf("accepted %s", extra)
		}
	}
	disabled := []byte(geoProfile + "# [Rule]\n# GeoIP = missing\n# Action = direct\n")
	if _, err := LoadConfigData(disabled); err != nil {
		t.Fatal("disabled rule requires resource", err)
	}
	// Errors do not include configuration secrets or host-local paths.
	_, err := LoadConfigDataWithGeoData([]byte(geoProfile+geoRules), []byte("bad"), site)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal(err)
	}
	caps := PlatformCapabilities()
	if !caps.GeoIPSplit || !caps.GeoSiteSplit || caps.GeoDataSchema == "" || caps.IKEv2.IPSplit {
		t.Fatal(caps)
	}
	// Config snapshots retain identifiers for adapters, rather than expanding IP ranges.
	cfg, err := LoadConfigDataWithGeoData([]byte(geoProfile+geoRules), ip, site)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(cfg.Policy.Config().Rules[0].GeoSite), []byte("test")) {
		t.Fatal(cfg.Policy.Config())
	}
}

func TestGeoDataProgrammaticKillSwitchGuard(t *testing.T) {
	ip, site := geoFixtures()
	cfg, err := LoadConfigDataWithGeoData([]byte(geoProfile+geoRules), ip, site)
	if err != nil {
		t.Fatal(err)
	}
	cfg.KillSwitch = true
	if err := cfg.validate(); err == nil {
		t.Fatal("programmatic configuration bypassed guard")
	}
}

func TestGeoDataFileErrorsLocateDataset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.conf")
	if err := os.WriteFile(path, []byte(geoProfile+"[Rule]\nGeoIP = zz\nAction = direct\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	var details *GeoDataError
	if !errors.As(err, &details) || details.Code != "geodata_unreadable" || details.Kind != "geoip" {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), dir) {
		t.Fatal("host-local path exposed", err)
	}
	ip, site := geoFixtures()
	_, err = LoadConfigDataWithGeoData([]byte(geoProfile+"[Rule]\nGeoSite = unknown\nAction = direct\n"), ip, site)
	details = nil
	if !errors.As(err, &details) || details.Code != "geodata_group_unknown" || details.Kind != "geosite" || details.Rule != 1 || details.Group != "unknown" {
		t.Fatalf("%v", err)
	}
}
