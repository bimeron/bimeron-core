package captiveportal

import (
	"context"
	"testing"
)

func TestDNSRequiresMatchingHandshakeFailure(t *testing.T) {
	for _, tc := range []struct {
		name, host, resolved, failed string
		want                         bool
	}{
		{"private", "peer.test", "192.168.77.1:51820", "192.168.77.1:51820", true},
		{"shared", "peer.test", "100.64.0.1:51820", "100.64.0.1:51820", true},
		{"link local", "peer.test", "[fe80::1]:443", "[fe80::1]:443", true},
		{"literal", "192.168.77.1", "192.168.77.1:51820", "192.168.77.1:51820", false},
		{"public", "peer.test", "203.0.113.1:443", "203.0.113.1:443", false},
		{"loopback", "peer.test", "127.0.0.1:443", "127.0.0.1:443", false},
		{"different endpoint", "peer.test", "192.168.77.1:443", "192.168.77.1:444", false},
		{"DNS alone", "peer.test", "192.168.77.1:443", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, observation := Observe(t.Context())
			Resolved(ctx, tc.host, tc.resolved)
			if tc.failed != "" {
				Failed(ctx, tc.failed, false)
			}
			if observation.Suspected() != tc.want {
				t.Fatalf("suspected = %v, want %v", observation.Suspected(), tc.want)
			}
		})
	}
}

func TestCanceledOrOtherAttemptEvidence(t *testing.T) {
	ctx, first := Observe(t.Context())
	Resolved(ctx, "peer.test", "192.168.77.1:443")
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	Failed(ctx, "192.168.77.1:443", true)
	ctx, second := Observe(t.Context())
	Failed(ctx, "192.168.77.1:443", false)
	if first.Suspected() || second.Suspected() {
		t.Fatal("canceled or unrelated attempt produced a hint")
	}
}

func BenchmarkCaptivePortalEvidence(b *testing.B) {
	for b.Loop() {
		ctx, observation := Observe(context.Background())
		Resolved(ctx, "peer.test", "192.168.77.1:51820")
		Failed(ctx, "192.168.77.1:51820", false)
		if !observation.Suspected() {
			b.Fatal("matching evidence was lost")
		}
	}
}
