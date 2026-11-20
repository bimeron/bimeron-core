package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var heldProfile = strings.Repeat("0f", 32)

// The record stores only a valid profile id and survives a reread.
func TestUpdateHoldRecord(t *testing.T) {
	h := UpdateHold{Path: filepath.Join(t.TempDir(), "hold.json")}
	if h.Read() != "" || h.Clear() != nil {
		t.Fatal("missing record misread")
	}
	if err := h.Write("../profile.conf"); err == nil {
		t.Fatal("invalid profile id recorded")
	}
	if err := h.Write(heldProfile); err != nil || h.Read() != heldProfile {
		t.Fatal("record not read back", err)
	}
	if err := os.WriteFile(h.Path, []byte(`{"version":2,"profile_id":"`+heldProfile+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if h.Read() != "" {
		t.Fatal("unknown record version accepted")
	}
	if err := h.Clear(); err != nil || h.Read() != "" {
		t.Fatal("record not cleared", err)
	}
}

// Residual protection kept across an update reports the held profile. The
// record survives a run that installs no protection and a probe that cannot
// tell residual from owned protection; a run that arms protection consumes
// it, and it is removed once no protection is installed.
func TestResidualProtectionReportsUpdateHold(t *testing.T) {
	h := &UpdateHold{Path: filepath.Join(t.TempDir(), "hold.json")}
	if err := h.Write(heldProfile); err != nil {
		t.Fatal(err)
	}
	found, installed := true, true
	b := &protectedBackend{fakeBackend: fakeBackend{open: func(context.Context) (session, error) { return fakeSession{}, nil }}}
	e := testEngine(b)
	e.factory = func(cfg SessionConfig) backend {
		if !cfg.KillSwitch {
			return &b.fakeBackend
		}
		return b
	}
	e.opts.ResidualProtection = true
	e.opts.UpdateHold = h
	e.residualProbe = func() (bool, error) { return found, nil }
	e.installedProbe = func() (bool, error) { return installed, nil }
	again := func() Status {
		e.mu.Lock()
		e.residualChecked = e.residualChecked.AddDate(-1, 0, 0)
		e.mu.Unlock()
		return e.Status()
	}
	s := e.Status()
	if s.KillSwitch != KillSwitchResidual || s.ResidualReason != ResidualUpdate || s.ResidualProfile != heldProfile || s.LastError != "cleanup_failed_run_recover" {
		t.Fatal("held profile not reported", s)
	}
	ctx := testDeadline(t)
	// A run without protection leaves the record for the client to retry.
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	if h.Read() != heldProfile {
		t.Fatal("unprotected start consumed the record")
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if h.Read() != heldProfile {
		t.Fatal("record consumed by a run that installed no protection")
	}
	// Protection owned by another process is not residual, but is installed.
	found = false
	if s := again(); s.ResidualProfile != "" || h.Read() != heldProfile {
		t.Fatal("record dropped while protection is still installed", s)
	}
	// A run that arms protection replaces it and consumes the record.
	found = true
	if err := e.Start(ctx, killSwitchConfig()); err != nil {
		t.Fatal(err)
	}
	if h.Read() != "" {
		t.Fatal("record survived a protected run")
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s := again(); s.KillSwitch != KillSwitchResidual || s.ResidualReason != "" || s.ResidualProfile != "" {
		t.Fatal("consumed record still reported", s)
	}
	// Without any installed protection a stale record is removed.
	if err := h.Write(heldProfile); err != nil {
		t.Fatal(err)
	}
	found, installed = false, false
	if s := again(); s.KillSwitch != "" || s.ResidualProfile != "" || h.Read() != "" {
		t.Fatal("record outlived the protection", s)
	}
}
