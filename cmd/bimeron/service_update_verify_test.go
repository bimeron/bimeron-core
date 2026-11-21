package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
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

func TestKeptUpdateReadiness(t *testing.T) {
	held := core.Status{State: core.Failed, KillSwitch: core.KillSwitchResidual, ResidualReason: core.ResidualUpdate, ResidualProfile: strings.Repeat("af", 32), LastError: "cleanup_failed_run_recover"}
	for _, tc := range []struct {
		name        string
		kept, ready bool
		change      func(*control.Response)
	}{
		{"kept", true, true, nil},
		{"not kept", false, false, nil},
		{"invalid profile", true, false, func(a *control.Response) { a.Status.ResidualProfile = strings.ToUpper(held.ResidualProfile) }},
		{"other failure", true, false, func(a *control.Response) { a.Status.LastError = "other" }},
		{"missing reason", true, false, func(a *control.Response) { a.Status.ResidualReason = "" }},
		{"missing residual", true, false, func(a *control.Response) { a.Status.KillSwitch = "" }},
		{"foreign instance", true, false, func(a *control.Response) { a.Instance = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := control.Response{Version: control.Version, Instance: "service", Status: held}
			if tc.change != nil {
				tc.change(&a)
			}
			if err := validateServiceStatus(a, "service", tc.kept); (err == nil) != tc.ready {
				t.Fatalf("readiness error = %v, want ready = %v", err, tc.ready)
			}
		})
	}
}
