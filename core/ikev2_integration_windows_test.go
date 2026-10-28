//go:build windows

package core

import (
	"context"
	"os"
	"testing"
	"time"
)

// This opt-in test uses a disposable, pre-provisioned Windows account/profile
// and a controlled IKEv2 server. It changes the machine's active VPN/routes.
// Never set this variable on shared/general-purpose CI workers.
func TestWindowsIKEv2NativeLifecycle(t *testing.T) {
	path := os.Getenv("BIMERON_IKEV2_TEST_CONFIG")
	if path == "" {
		t.Skip("set BIMERON_IKEV2_TEST_CONFIG only on an isolated Windows VPN test machine")
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal("could not load isolated IKEv2 test configuration")
	}
	if cfg.IKEv2 == nil {
		t.Fatal("isolated test requires an IKEv2 profile")
	}
	e := New(Options{})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		if err := e.Stop(ctx); err != nil {
			t.Error("native IKEv2 cleanup failed", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := e.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		status := e.Status()
		if status.State == Connected {
			if status.Session == nil || status.Session.Backend != "ikev2" || !e.Stats().Unavailable {
				t.Fatal("incorrect native session metadata")
			}
			break
		}
		if status.State == Failed {
			t.Fatal("native IKEv2 startup failed", status.LastError)
		}
		select {
		case <-ctx.Done():
			t.Fatal("native IKEv2 startup timed out")
		case <-ticker.C:
		}
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer stopCancel()
	if err := e.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	if e.Status().State != Disconnected {
		t.Fatal("native IKEv2 did not finish cleanup")
	}
}
