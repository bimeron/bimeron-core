package core

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"
)

type failingRecovery struct {
	fakeSession
	retries atomic.Int32
}

func (s *failingRecovery) Wait(context.Context) error { return fault("network_changed", true) }
func (s *failingRecovery) Suspend()                   {}
func (s *failingRecovery) Reconnect(context.Context) error {
	s.retries.Add(1)
	return fault("transport_check_failed", true)
}

func TestReconnectBudgetExhaustion(t *testing.T) {
	for _, mode := range []string{"initial", "ordinary", "persistent", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			var opens, closes atomic.Int32
			p := &failingRecovery{fakeSession: fakeSession{close: func() error {
				closes.Add(1)
				if mode == "cleanup" {
					return fault("cleanup_failed_run_recover", false)
				}
				return nil
			}}}
			e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
				n := opens.Add(1)
				if mode == "persistent" || mode == "cleanup" {
					return p, nil
				}
				if mode == "ordinary" && n == 1 {
					return fakeSession{wait: p.Wait, close: func() error { closes.Add(1); return nil }}, nil
				}
				return nil, fault("transport_check_failed", true)
			}})
			ctx := testDeadline(t)
			if err := e.Start(ctx, testConfig()); err != nil {
				t.Fatal(err)
			}
			if err := e.Wait(ctx); err == nil {
				t.Fatal("missing terminal error")
			}
			status := e.Status()
			expected := "transport_check_failed"
			if mode == "cleanup" {
				expected = "cleanup_failed_run_recover"
			}
			if status.State != Failed || status.LastError != expected || status.ReconnectAttempt != 3 || status.ReconnectLimit != 3 {
				t.Fatal(status)
			}
			if mode == "initial" || mode == "ordinary" {
				if opens.Load() != 4 || status.Attempt != 4 {
					t.Fatal("expected initial + three retries", opens.Load(), status)
				}
			} else if opens.Load() != 1 || p.retries.Load() != 3 || closes.Load() != 1 {
				t.Fatal("persistent retry escaped budget")
			}
			progress := []int{}
			for len(e.Events()) > 0 {
				ev := <-e.Events()
				if ev.Code == "reconnect_attempt" {
					data, err := json.Marshal(ev)
					if err != nil {
						t.Fatal(err)
					}
					var wire map[string]any
					if err := json.Unmarshal(data, &wire); err != nil {
						t.Fatal(err)
					}
					if wire["ReconnectAttempt"] != float64(ev.ReconnectAttempt) || wire["ReconnectLimit"] != float64(3) {
						t.Fatal(string(data))
					}
					progress = append(progress, ev.ReconnectAttempt)
					if ev.ReconnectLimit != 3 || ev.LastError == "" {
						t.Fatal(ev)
					}
				}
			}
			if len(progress) != 3 || progress[0] != 1 || progress[1] != 2 || progress[2] != 3 {
				t.Fatal(progress)
			}
			data, err := json.Marshal(status)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]any
			if err := json.Unmarshal(data, &wire); err != nil {
				t.Fatal(err)
			}
			if wire["ReconnectAttempt"] != float64(3) || wire["ReconnectLimit"] != float64(3) {
				t.Fatal(string(data))
			}
		})
	}
}

func TestReconnectBudgetResetsAfterSuccess(t *testing.T) {
	var opens atomic.Int32
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		n := opens.Add(1)
		if n == 1 || n == 4 {
			return fakeSession{wait: func(context.Context) error { return fault("network_changed", true) }}, nil
		}
		if n == 7 {
			return fakeSession{}, nil
		}
		return nil, fault("transport_check_failed", true)
	}})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Reconnecting)
	awaitState(t, e, Connected)
	awaitState(t, e, Reconnecting)
	awaitState(t, e, Connected)
	if s := e.Status(); s.ReconnectAttempt != 0 || s.ReconnectLimit != 0 {
		t.Fatal(s)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestStopDuringReconnectBackoffClearsProgress(t *testing.T) {
	var opens atomic.Int32
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) {
		opens.Add(1)
		return nil, fault("transport_check_failed", true)
	}})
	e.opts.RetryMin = time.Hour
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Reconnecting)
	if s := e.Status(); s.ReconnectAttempt != 1 || s.ReconnectLimit != 3 {
		t.Fatal(s)
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s := e.Status(); s.State != Disconnected || s.ReconnectAttempt != 0 || s.ReconnectLimit != 0 || opens.Load() != 1 {
		t.Fatal(s, opens.Load())
	}
	data, err := json.Marshal(e.Status())
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if _, present := wire["ReconnectAttempt"]; present {
		t.Fatal(string(data))
	}
}
