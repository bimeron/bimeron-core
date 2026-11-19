package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateJSONBridgeReportsTrustFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "draft.conf")
	profile := "[Profile]\nVersion = 1\n\n[AccessKey]\nSSH = ssh://alice@example.com?known_hosts=kh\nIdentityFile = keys/id\n"
	if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := validateJSONBridge(path, &out); err != nil {
		t.Fatal(err)
	}
	var r struct {
		Version    int               `json:"version"`
		Problems   []json.RawMessage `json:"problems"`
		TrustFiles []struct {
			Kind, Source, Path string
		} `json:"trust_files"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || r.Version != 1 || r.Problems == nil || len(r.Problems) != 0 {
		t.Fatalf("%s %v", out.String(), err)
	}
	want := []struct{ Kind, Source, Path string }{
		{"ssh_identity", "option", filepath.Join(dir, "keys", "id")},
		{"ssh_known_hosts", "uri", filepath.Join(dir, "kh")},
	}
	if len(r.TrustFiles) != len(want) {
		t.Fatalf("trust_files = %+v", r.TrustFiles)
	}
	for i := range want {
		if r.TrustFiles[i] != want[i] {
			t.Fatalf("trust_files[%d] = %+v, want %+v", i, r.TrustFiles[i], want[i])
		}
	}

	// A failing profile reports problems but no trust files.
	if err := os.WriteFile(path, []byte(profile+"\n[Interface]\nName = 1bad\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := validateJSONBridge(path, &out); err != nil || strings.Contains(out.String(), "trust_files") || !strings.Contains(out.String(), "interface_name_invalid") {
		t.Fatalf("%s %v", out.String(), err)
	}
}
