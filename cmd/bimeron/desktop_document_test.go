package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocumentBridge(t *testing.T) {
	profile := "\ufeff[Unknown]\r\nSecret = untouched\r\n[Routing]\r\nDefault = proxy\r\n[Rule]\r\nDomain=example.com\r\nAction=direct"
	call := func(ops string) bridgeResponse {
		t.Helper()
		p, _ := json.Marshal(profile)
		var out bytes.Buffer
		if err := documentBridge(strings.NewReader(`{"version":1,"profile":`+string(p)+`,"operations":`+ops+`}`), &out); err != nil {
			t.Fatal(err)
		}
		var r bridgeResponse
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := call(`[]`)
	if r.Error != "" || *r.Profile != profile {
		t.Fatalf("inspect: %+v", r)
	}
	r = call(`[{"op":"set_field","section":"Routing","key":"Default","value":"block"},{"op":"add","index":0,"matcher":"GeoIP","value":"ru","action":"direct","enabled":false},{"op":"move","index":0,"to":1},{"op":"delete","index":0}]`)
	if r.Error != "" || !strings.Contains(*r.Profile, "Secret = untouched\r\n") || !strings.Contains(*r.Profile, "# GeoIP=ru\r\n") {
		t.Fatalf("edit: %+v", r)
	}
	r = call(`[{"op":"delete","index":0},{"op":"delete","index":99}]`)
	if r.Error == "" || *r.Profile != profile {
		t.Fatal("failed batch changed draft")
	}
	for _, input := range []string{`{}`, `{"version":2,"profile":"","operations":[]}`, `{"version":1,"profile":"","operations":[{"op":"delete"}]}`, `{"version":1,"profile":"","operations":[]} {}`, strings.Repeat("x", (1<<20)+1)} {
		var out bytes.Buffer
		if err := documentBridge(strings.NewReader(input), &out); err != nil {
			t.Fatal(err)
		}
		var r bridgeResponse
		if json.Unmarshal(out.Bytes(), &r) != nil || r.Error == "" {
			t.Fatal("accepted invalid request")
		}
	}
}
func TestGeoDataBridgeArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"groups", "geoip", "relative.dat"}, {"groups", "unknown", "/tmp/data"}} {
		var out bytes.Buffer
		if err := geoDataBridge(args, &out); err != nil {
			t.Fatal(err)
		}
		var r bridgeResponse
		if json.Unmarshal(out.Bytes(), &r) != nil || r.Error == "" || r.Groups == nil {
			t.Fatal(out.String())
		}
	}
}

func TestGeoDataBridgeFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geoip.dat")
	// GeoIPList: one ZZ group with a 203.0.113.0/24 entry.
	data := []byte{10, 16, 10, 2, 'Z', 'Z', 18, 10, 10, 4, 203, 0, 113, 0, 16, 24}
	// The outer/group entry lengths are 14 and 8 bytes respectively.
	data[1] = 14
	data[7] = 8
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := geoDataBridge([]string{"groups", "geoip", path}, &out); err != nil {
		t.Fatal(err)
	}
	var r bridgeResponse
	if json.Unmarshal(out.Bytes(), &r) != nil || r.Error != "" || r.Groups == nil || len(*r.Groups) != 1 || (*r.Groups)[0] != "zz" {
		t.Fatal(out.String())
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate((64 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	out.Reset()
	geoDataBridge([]string{"groups", "geoip", path}, &out)
	if json.Unmarshal(out.Bytes(), &r) != nil || r.Error == "" || r.Details == nil {
		t.Fatal(out.String())
	}
}

func TestValidateJSONBridge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "draft.conf")
	profile := "[Profile]\nVersion=1\n[AccessKey]\nKey=ss://aes-256-gcm:secret@127.0.0.1:8388\n"
	if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := validateJSONBridge(path, &out); err != nil || out.String() != "{\"version\":1}\n" {
		t.Fatalf("%s %v", out.String(), err)
	}
	profile += "[GeoData]\nGeoIPFile=missing.dat\n[Rule]\nGeoIP=zz\nAction=direct\n"
	if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	validateJSONBridge(path, &out)
	var r bridgeResponse
	if json.Unmarshal(out.Bytes(), &r) != nil || r.Error == "" || r.Details == nil || r.Details.Code != "geodata_unreadable" || strings.Contains(out.String(), "secret") {
		t.Fatal(out.String())
	}
}
