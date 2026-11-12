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
func TestDocumentBridgeAccessConversion(t *testing.T) {
	const profile = "[Profile]\nVersion = 1\n\n[AccessKey]\nHysteria2 = hy2://secret@example.com:443?sni=front.example\n"
	call := func(profile, ops string) bridgeResponse {
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
	r := call(profile, `[{"op":"access_to_fields"}]`)
	if r.Error != "" || !strings.Contains(*r.Profile, "Type = hysteria2\nServer = example.com\nPort = 443\nPassword = secret\nServerName = front.example\n") {
		t.Fatalf("to fields: %+v", r)
	}
	if !strings.Contains(string(r.Fields), `"AccessKey/Type":"hysteria2"`) {
		t.Fatalf("fields: %s", r.Fields)
	}
	r = call(*r.Profile, `[{"op":"access_to_uri"}]`)
	if r.Error != "" || *r.Profile != "[Profile]\nVersion = 1\n\n[AccessKey]\nHysteria2 = hysteria2://secret@example.com:443?sni=front.example\n" {
		t.Fatalf("to uri: %+v", r)
	}
	// Unknown members and failed conversions leave the draft unchanged.
	for _, ops := range []string{`[{"op":"access_to_fields","index":0}]`, `[{"op":"access_to_uri"}]`, `[{"op":"set_field","section":"Profile","key":"Name","value":"x"},{"op":"access_to_uri"}]`} {
		r = call(profile, ops)
		if r.Error == "" || *r.Profile != profile {
			t.Fatalf("%s: %+v", ops, r)
		}
	}
	if r.Problems == nil || len(*r.Problems) != 1 || (*r.Problems)[0].Code != "access_conversion_unsupported" {
		t.Fatalf("problems: %+v", r.Problems)
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
	if err := validateJSONBridge(path, &out); err != nil || out.String() != "{\"version\":1,\"problems\":[]}\n" {
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
	if r.Problems == nil || len(*r.Problems) != 1 || (*r.Problems)[0].Code != "geodata_unreadable" {
		t.Fatal(out.String())
	}
}

func TestValidateJSONBridgeLocatesProblems(t *testing.T) {
	path := filepath.Join(t.TempDir(), "draft.conf")
	profile := "[Profile]\nVersion = 1\n\n[AccessKey]\nSS = ss://aes-256-gcm:secret@127.0.0.1:8388\n\n[Interface]\nName = 1bad\n"
	if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := validateJSONBridge(path, &out); err != nil {
		t.Fatal(err)
	}
	var r bridgeResponse
	if json.Unmarshal(out.Bytes(), &r) != nil || r.Problems == nil || len(*r.Problems) != 1 || strings.Contains(out.String(), "secret") {
		t.Fatal(out.String())
	}
	p := (*r.Problems)[0]
	if p.Code != "interface_name_invalid" || p.Section != "Interface" || p.Field != "Name" || p.Line != 8 || p.Value != "present" || p.Args["max"] != "32" {
		t.Fatalf("%+v", p)
	}
	out.Reset()
	if err := validateJSONBridge("relative.conf", &out); err != nil || !strings.Contains(out.String(), `"code":"invalid_request"`) {
		t.Fatal(out.String(), err)
	}
}

func TestErrorCatalogCommand(t *testing.T) {
	var out bytes.Buffer
	if err := errorCatalog([]string{"--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var c struct {
		Version int
		Codes   map[string]struct{ Kind, EN, RU string }
	}
	if err := json.Unmarshal(out.Bytes(), &c); err != nil || c.Version != 1 || c.Codes["interface_name_invalid"].RU == "" {
		t.Fatal(out.String(), err)
	}
	if errorCatalog(nil, &out) == nil || errorCatalog([]string{"--text"}, &out) == nil {
		t.Fatal("errors accepted invalid arguments")
	}
}
