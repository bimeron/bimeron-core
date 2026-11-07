package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"bimeron/internal/problem"
	"bimeron/internal/sshtunnel"
)

// failureCode matches every code literal that the core can place into
// Status.LastError: fault and stageError literals, and fallbacks passed to
// codeFault and macosFault. Files for every GOOS are scanned as text.
var failureCode = regexp.MustCompile(`\bfault\(\s*"([a-z0-9_]+)"|\b(?:codeFault|macosFault)\([^,()]+,\s*"([a-z0-9_]+)"|stageError\{code:\s*"([a-z0-9_]+)"|&Failure\{"([a-z0-9_]+)"`)

func TestFailureCodesAreCatalogCodes(t *testing.T) {
	var files []string
	for _, pattern := range []string{"*.go", filepath.Join("..", "internal", "hysteria2", "*.go")} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	found := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range failureCode.FindAllStringSubmatch(string(data), -1) {
			code := m[1] + m[2] + m[3] + m[4]
			found++
			if !problem.Known(code) {
				t.Errorf("%s: failure code %q has no catalog entry", path, code)
			}
		}
	}
	if found < 50 {
		t.Fatalf("scanned only %d failure codes; the pattern no longer matches the source", found)
	}
	if !problem.Known(connectionFailed) {
		t.Fatalf("generic code %q has no catalog entry", connectionFailed)
	}
}

// TestSSHHostKeyCodesAreCatalogCodes covers the codes that sshFault forwards
// from sshtunnel.HostKeyError, which the literal scan above cannot see.
func TestSSHHostKeyCodesAreCatalogCodes(t *testing.T) {
	c := problem.MustLoad()
	for _, code := range []string{
		sshtunnel.HostKeyMismatch, sshtunnel.HostKeyRejected, sshtunnel.HostKeyUnanswered,
		sshtunnel.HostKeyUnknown, sshtunnel.HostKeyCARequired, sshtunnel.KnownHostsMissing,
	} {
		entry, ok := c.Codes[code]
		if !ok || entry.Kind != problem.KindConnection {
			t.Errorf("host-key code %q has catalog entry %+v, %v; want kind connection", code, entry, ok)
		}
		err := sshFault(&sshtunnel.HostKeyError{Code: code}, SessionConfig{SSHProfileOnly: true})
		if got := lastErrorCode(err); got != code || retryable(err) {
			t.Errorf("sshFault(%q) LastError = %q retry %v", code, got, retryable(err))
		}
	}
}

func TestCodeFaultNeverForwardsFreeText(t *testing.T) {
	for _, tc := range []struct {
		err   error
		want  string
		retry bool
	}{
		{errors.New("cannot configure systemd-resolved for 192.0.2.1"), "network_setup_failed", false},
		{errors.New("linux_recovery_failed: secret detail"), "network_setup_failed", false},
		{errors.New("network_unavailable"), "network_unavailable", true},
		{errors.New("ikev2_server_unreachable"), "ikev2_server_unreachable", false},
		{errors.New("not_a_catalog_code"), "network_setup_failed", false},
		{nil, "network_setup_failed", false},
	} {
		err := codeFault(tc.err, "network_setup_failed", tc.retry)
		if err.Error() != tc.want || retryable(err) != tc.retry || !problem.Known(err.Error()) {
			t.Errorf("codeFault(%v) = %q retry %v, want %q retry %v", tc.err, err, retryable(err), tc.want, tc.retry)
		}
	}
	// A coded stageError keeps its own retry flag and stage.
	staged := &stageError{code: "hysteria2_network_failed", retry: true, stage: "endpoint_resolution"}
	if got := codeFault(staged, "network_setup_failed", false); got != error(staged) {
		t.Fatalf("codeFault(staged) = %#v", got)
	}
	if got := codeFault(fault("unknown_internal_code", true), "network_setup_failed", false); got.Error() != "network_setup_failed" || retryable(got) {
		t.Fatalf("codeFault(uncoded stageError) = %q retry %v", got, retryable(got))
	}
}

func TestLastErrorIsAlwaysCatalogCode(t *testing.T) {
	secret := "dial tcp 192.0.2.1:443: connection refused (password=secret)"
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		return fakeSession{wait: func(context.Context) error { return errors.New(secret) }}, nil
	}})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	_ = e.Wait(ctx)
	status := e.Status()
	if status.State != Failed || status.LastError != connectionFailed || status.ErrorStage != "" {
		t.Fatalf("status = %+v", status)
	}
	for {
		select {
		case event := <-e.Events():
			if strings.Contains(event.LastError+event.Message, "secret") || (event.LastError != "" && !problem.Known(event.LastError)) {
				t.Fatalf("event leaked uncoded text: %+v", event)
			}
			continue
		default:
		}
		break
	}

	e = testEngine(fakeBackend{open: func(context.Context) (session, error) {
		return nil, fault("ikev2_disconnected", false)
	}})
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	_ = e.Wait(ctx)
	if got := e.Status().LastError; got != "ikev2_disconnected" {
		t.Fatalf("catalog code was replaced: %q", got)
	}
}
