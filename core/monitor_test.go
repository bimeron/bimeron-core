package core

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNetworkMonitor(t *testing.T) {
	for _, tc := range []struct {
		name, identity string
		inspectErr     error
		gap            time.Duration
		want           string
		retry          bool
	}{
		{"stable", "ethernet", nil, 5 * time.Second, "", false},
		{"wifi_switch", "wifi", nil, 5 * time.Second, "network_changed", true},
		{"new_gateway", "ethernet-new-gateway", nil, 5 * time.Second, "network_changed", true},
		{"offline", "", errors.New("offline"), 5 * time.Second, "network_unavailable", true},
		{"permanent", "", fault("macos_dns_changed_externally", false), 5 * time.Second, "macos_dns_changed_externally", false},
		{"resume", "ethernet", nil, time.Minute, "resume_detected", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			m := healthMonitor{identity: "ethernet", last: start, lastProbe: start,
				inspect: func(context.Context) (string, error) { return tc.identity, tc.inspectErr }}
			err := m.step(context.Background(), start.Add(tc.gap))
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || err.Error() != tc.want || retryable(err) != tc.retry {
				t.Fatal(err)
			}
		})
	}
}
func TestHealthProbeConsecutiveFailures(t *testing.T) {
	now := time.Now()
	start := now
	probes := 0
	m := healthMonitor{identity: "network", last: now, lastProbe: now, clock: func() time.Time { return now }, report: func(string, string) {},
		inspect: func(context.Context) (string, error) { return "network", nil },
		probe: func(ctx context.Context) error {
			probes++
			if _, ok := ctx.Deadline(); !ok {
				t.Error("unbounded probe")
			}
			if probes == 3 {
				return nil
			}
			return errors.New("probe failed")
		},
	}
	// Two failures, a recovery, then three consecutive failures trigger reconnect.
	for i := 1; i <= 36; i++ {
		now = start.Add(time.Duration(i) * 5 * time.Second)
		err := m.step(context.Background(), now)
		if i < 36 && err != nil {
			t.Fatalf("early retry at %d: %v", i, err)
		}
		if i == 36 && (err == nil || err.Error() != "transport_unavailable") {
			t.Fatal(err)
		}
	}
	if probes != 6 {
		t.Fatal(probes)
	}
}
func TestMonitorCancellationDuringInspection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now()
	m := healthMonitor{last: now, lastProbe: now, inspect: func(context.Context) (string, error) { cancel(); return "", errors.New("cancelled") }}
	if err := m.step(ctx, now.Add(time.Second)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
