package core

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type protectionTestSession struct {
	steps *[]string
	fail  bool
}

func (s protectionTestSession) Wait(ctx context.Context) error { return ctx.Err() }
func (s protectionTestSession) Close() error {
	*s.steps = append(*s.steps, "ras")
	if s.fail {
		return errors.New("native failure")
	}
	return nil
}

type protectionTestGuard struct{ steps *[]string }

func (g protectionTestGuard) Close() error  { *g.steps = append(*g.steps, "remove-wfp"); return nil }
func (g protectionTestGuard) Retain() error { *g.steps = append(*g.steps, "retain-wfp"); return nil }

func TestNativeProtectionCleanupOrderingAndRetention(t *testing.T) {
	for _, mode := range []string{"stop", "crash", "loss", "native-error", "dns-error"} {
		t.Run(mode, func(t *testing.T) {
			steps := []string{}
			s := &protectedIKEv2Session{native: protectionTestSession{&steps, mode == "native-error"}, guard: protectionTestGuard{&steps}, cleanupDNS: func() error {
				steps = append(steps, "dns")
				if mode == "dns-error" {
					return errors.New("DNS failure")
				}
				return nil
			}}
			if mode == "loss" {
				s.Wait(context.Background())
			} else {
				ctx, cancel := context.WithCancelCause(context.Background())
				if mode == "crash" {
					cancel(errGuardedPanic)
				} else {
					cancel(nil)
				}
				s.Wait(ctx)
			}
			err := s.Close()
			again := s.Close()
			want := []string{"ras", "dns", "remove-wfp"}
			if mode == "loss" || mode == "crash" || mode == "native-error" {
				want = []string{"ras", "retain-wfp"}
			}
			if mode == "dns-error" {
				want = []string{"ras", "dns", "retain-wfp"}
			}
			if !reflect.DeepEqual(steps, want) || (err != nil) != (mode != "stop") || again != err {
				t.Fatal(steps, want, err, again)
			}
		})
	}
}

// DNS setup finishes under an independent timeout. Open handles cancellation
// by calling Close directly, before the engine can call Wait.
func TestNativeCloseAfterDNSSetupCancellation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		want  []string
	}{
		{"crash", errGuardedPanic, []string{"ras", "retain-wfp"}},
		{"stop", context.Canceled, []string{"ras", "dns", "remove-wfp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			var steps []string
			s := &protectedIKEv2Session{
				setupContext: ctx, native: protectionTestSession{steps: &steps},
				guard:      protectionTestGuard{&steps},
				cleanupDNS: func() error { steps = append(steps, "dns"); return nil },
			}
			cancel(tc.cause)
			err := s.Close()
			if (err != nil) != (tc.cause == errGuardedPanic) || !reflect.DeepEqual(steps, tc.want) {
				t.Fatalf("cleanup %v, error %v", steps, err)
			}
		})
	}
}
