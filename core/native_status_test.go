package core

import (
	"context"
	"errors"
	"testing"
)

func TestNativeCleanupSnapshotTracksRetentionWithoutEvents(t *testing.T) {
	for _, failure := range []bool{false, true} {
		n := NativeStatus{Requested: true, WFP: "active", DNS: "active"}
		steps := []string{}
		s := &protectedIKEv2Session{native: protectionTestSession{&steps, failure}, guard: protectionTestGuard{&steps}, cleanupDNS: func() error { return nil }, update: func(f func(*NativeStatus)) { f(&n) }}
		_ = s.Close()
		if failure {
			if !n.RecoveryRequired || n.WFP != "retained" || n.RASCleanup != "failed" {
				t.Fatal(n)
			}
		} else if n.WFP != "inactive" || n.DNS != "inactive" || n.WFPCleanup != "succeeded" {
			t.Fatal(n)
		}
	}
}

func TestNativeStatusIsCopied(t *testing.T) {
	e := New(Options{})
	e.status.Native = &NativeStatus{WFP: "retained"}
	snapshot := e.Status()
	snapshot.Native.WFP = "inactive"
	if e.Status().Native.WFP != "retained" {
		t.Fatal("caller mutated authoritative status")
	}
}

type failingNative struct{}

func (failingNative) Wait(context.Context) error { return nil }
func (failingNative) Close() error               { return errors.New("private") }

func TestUnprotectedCleanupFailureIsObservable(t *testing.T) {
	n := NativeStatus{}
	s := &observedNativeSession{native: failingNative{}, config: SessionConfig{nativeUpdate: func(f func(*NativeStatus)) { f(&n) }}}
	if s.Close() == nil || n.RASCleanup != "failed" {
		t.Fatal(n)
	}
}

func TestEngineEventLossIsCounted(t *testing.T) {
	e := New(Options{})
	e.mu.Lock()
	for i := 0; i < 130; i++ {
		e.emitLocked("state", "connecting")
	}
	e.mu.Unlock()
	if e.EventDrops() != 2 {
		t.Fatal("source event loss hidden")
	}
}
