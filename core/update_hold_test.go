package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var requireHoldWriter = func(*testing.T) {}

var heldProfile = strings.Repeat("0f", 32)

// A handover blocks in Acquire while the update stop arrives. Only the new
// run can be recorded after the handover completes.
type gatedHoldBackend struct {
	*protectedBackend
	entered, proceed chan struct{}
}

func (b *gatedHoldBackend) Acquire(ctx context.Context) (func(), error) {
	close(b.entered)
	select {
	case <-b.proceed:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return b.protectedBackend.Acquire(ctx)
}

func TestUpdateStopDuringHandover(t *testing.T) {
	ctx := testDeadline(t)
	old := &protectedBackend{fakeBackend: fakeBackend{open: func(context.Context) (session, error) { return fakeSession{}, nil }}}
	next := &gatedHoldBackend{protectedBackend: &protectedBackend{fakeBackend: old.fakeBackend}, entered: make(chan struct{}), proceed: make(chan struct{})}
	e := testEngine(old)
	cfg := killSwitchConfig()
	if err := e.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	e.factory = func(SessionConfig) backend { return next }
	cfg.ProfileID = heldProfile
	start := make(chan error, 1)
	go func() { start <- e.Start(ctx, cfg) }()
	select {
	case <-next.entered:
	case <-ctx.Done():
		t.Fatal("handover never entered acquire")
	}
	record := make(chan string, 1)
	stopped := make(chan error, 1)
	attempting := make(chan struct{})
	go func() {
		close(attempting)
		stopped <- e.MarkUpdateAbandon(func(id string) error { record <- id; return os.ErrPermission })
	}()
	<-attempting
	close(next.proceed)
	if err := <-start; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != os.ErrPermission {
		t.Fatal("missing marker error", err)
	}
	if id := <-record; id != heldProfile {
		t.Fatal("recorded wrong owner", id)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, retains, installed := next.snapshot(); retains != 1 || !installed {
		t.Fatal("record failure released filters")
	}
}

// The record stores only a valid profile id and survives a reread.
func TestUpdateHoldRecord(t *testing.T) {
	requireHoldWriter(t)
	h := UpdateHold{Path: filepath.Join(t.TempDir(), "hold.json"), filterGeneration: testFilterGeneration}
	if h.Read() != "" || h.Clear() != nil {
		t.Fatal("missing record misread")
	}
	if err := h.Write("../profile.conf"); err == nil {
		t.Fatal("invalid profile id recorded")
	}
	if err := h.Write(heldProfile); err != nil || h.Read() != heldProfile {
		t.Fatal("record not read back", err)
	}
	if err := os.WriteFile(h.Path, []byte(`{"version":1,"profile_id":"`+heldProfile+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if h.Read() != "" {
		t.Fatal("unbound legacy marker accepted")
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
	requireHoldWriter(t)
	h := &UpdateHold{Path: filepath.Join(t.TempDir(), "hold.json"), filterGeneration: testFilterGeneration}
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

func testFilterGeneration() (string, error) { return "generation-A", nil }
