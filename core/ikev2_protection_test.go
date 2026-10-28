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
	for _, mode := range []string{"stop", "loss", "native-error", "dns-error"} {
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
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				s.Wait(ctx)
			}
			err := s.Close()
			again := s.Close()
			want := []string{"ras", "dns", "remove-wfp"}
			if mode == "loss" || mode == "native-error" {
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
