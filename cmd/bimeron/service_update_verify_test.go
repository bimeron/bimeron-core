package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"bimeron/core"
	"bimeron/internal/control"
)

func TestUpdateExpectationAndStagedDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new")
	if err := os.WriteFile(path, []byte("new executable"), 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("new executable"))
	want := hex.EncodeToString(h[:])
	expect, err := parseUpdateExpectation([]string{"-source", path, "-version", "0.2.0", "-sha256", want})
	if err != nil || expect.version != "0.2.0" || expect.source != path {
		t.Fatal(expect, err)
	}
	if err := verifyUpdateFile(path, expect.sha256); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyUpdateFile(path, expect.sha256); err == nil {
		t.Fatal("staged tampering accepted")
	}
	if _, err := parseUpdateExpectation([]string{"-source", path, "-version", "0.2.0"}); err == nil {
		t.Fatal("missing digest accepted")
	}
	if _, err := parseUpdateExpectation([]string{"-source", "relative", "-version", "0.2.0", "-sha256", want}); err == nil {
		t.Fatal("relative source accepted")
	}
}

func TestUpdatedHelloMustMatchVersionAndProtocol(t *testing.T) {
	a := control.Response{Version: control.Version, Core: &core.BuildDetails{Version: "0.2.0"}}
	if err := validateUpdatedHello(a, "0.2.0"); err != nil {
		t.Fatal(err)
	}
	a.Core.Version = "0.1.0"
	if err := validateUpdatedHello(a, "0.2.0"); err == nil {
		t.Fatal("wrong core version accepted")
	}
	a.Core.Version = "0.2.0"
	a.Version++
	if err := validateUpdatedHello(a, "0.2.0"); err == nil {
		t.Fatal("wrong IPC protocol accepted")
	}
	a.Version = control.Version
	a.Core = nil
	if err := validateUpdatedHello(a, "0.2.0"); err == nil {
		t.Fatal("missing core version accepted")
	}
}
