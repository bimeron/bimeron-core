package control

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"bimeron/core"
	"bimeron/internal/telemetry"
)

type snapshotEngine struct {
	fakeEngine
	snapshot core.StatsSnapshot
}

func (e *snapshotEngine) StatsSnapshot() core.StatsSnapshot { return e.snapshot }

func TestStatsSnapshotDispatch(t *testing.T) {
	e := &snapshotEngine{snapshot: core.StatsSnapshot{
		Status:   core.Status{State: core.Connected, Attempt: 2, Session: &core.SessionInfo{ID: "captured", Active: true}},
		Counters: &telemetry.Snapshot{BytesUp: 17},
	}}
	s := NewServer(e)
	for i := 0; i < 2; i++ {
		a := s.dispatch(context.Background(), Request{Version: Version, Command: "stats_snapshot", ID: "request"})
		if a.Error != "" || a.Instance != s.instance || a.ID != "request" || a.StatsSnapshot == nil || !reflect.DeepEqual(*a.StatsSnapshot, e.snapshot) || !reflect.DeepEqual(a.Status, e.snapshot.Status) {
			t.Fatalf("snapshot response: %+v", a)
		}
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Response
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded, a) {
			t.Fatalf("roundtrip: %s", data)
		}
	}
	for _, r := range []Request{
		{Version: Version, Command: "stats_snapshot", Config: "/config"},
		{Version: Version, Command: "stats_snapshot", After: 1},
		{Version: Version, Command: "stats_snapshot", ChallengeID: "challenge"},
		{Version: Version, Command: "stats_snapshot", Instance: s.instance},
	} {
		if a := s.dispatch(context.Background(), r); a.Error != "invalid_request" || a.StatsSnapshot != nil {
			t.Fatalf("invalid request accepted: %+v", a)
		}
	}
}

func TestStatsSnapshotCapability(t *testing.T) {
	for _, supported := range []bool{false, true} {
		var e Engine = &fakeEngine{}
		if supported {
			e = &snapshotEngine{}
		}
		s := NewServer(e)
		for _, command := range []string{"hello", "capabilities"} {
			a := s.dispatch(context.Background(), Request{Version: Version, Command: command})
			if a.Error != "" || a.SessionBoundStats != supported {
				t.Fatalf("%s supported=%v: %+v", command, supported, a)
			}
			data, err := json.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			if _, exists := fields["session_bound_stats"]; exists != supported {
				t.Fatalf("capability presence: %s", data)
			}
		}
		if !supported {
			if a := s.dispatch(context.Background(), Request{Version: Version, Command: "stats_snapshot"}); a.Error != "unknown_command" || a.StatsSnapshot != nil {
				t.Fatalf("legacy provider: %+v", a)
			}
		}
	}
}

func TestForegroundStatsSnapshot(t *testing.T) {
	e := &snapshotEngine{snapshot: core.StatsSnapshot{Status: core.Status{State: core.Disconnected}}}
	s := NewServer(e)
	s.foreground = true
	s.installation = "installation"
	r := Request{Version: Version, ID: "request", Installation: s.installation, Instance: s.instance, Command: "stats_snapshot"}
	if a := s.foregroundDispatcher(context.Background(), r); a.Error != "" || a.StatsSnapshot == nil || !reflect.DeepEqual(a.Status, e.snapshot.Status) {
		t.Fatalf("foreground snapshot: %+v", a)
	}
	hello := s.foregroundDispatcher(context.Background(), Request{Version: Version, ID: "hello", Installation: s.installation, Command: "hello"})
	if hello.Error != "" || !hello.SessionBoundStats {
		t.Fatalf("foreground capability: %+v", hello)
	}
	r.Instance = "stale"
	if a := s.foregroundDispatcher(context.Background(), r); a.Error != "stale_instance" || a.StatsSnapshot != nil {
		t.Fatalf("foreground guard: %+v", a)
	}
}
