package control

import (
	"bimeron/core"
	"bytes"
	"context"
	"testing"
	"time"
)

func TestIKEAuthOneShotAndRetirement(t *testing.T) {
	s, _, _ := authFixture(t)
	ctx, retire := s.ikeAuthority(context.Background())
	b := ikeBinding{"installation", "instance", "session", "attempt", "request", "profile", "vpn.example.com"}
	calls := 0
	if !s.beginIKEAuth(ctx, b, time.Minute, func(u, p []byte) { calls++ }) {
		t.Fatal("begin")
	}
	for i := 0; i < 2; i++ {
		u, p := []byte("sentinel-user"), []byte("sentinel-password")
		r := s.answerIKEAuth(ctx, b, ikePassword, ikeAttemptOnly, ikeSecrets{u, p})
		if r.accepted != (i == 0) || !bytes.Equal(u, make([]byte, len(u))) || !bytes.Equal(p, make([]byte, len(p))) {
			t.Fatal("one shot or clearing")
		}
	}
	retire()
	if calls != 1 || s.beginIKEAuth(ctx, b, time.Minute, func([]byte, []byte) {}) {
		t.Fatal("retired authority reused")
	}
}

func TestIKEAuthRejectedBuffers(t *testing.T) {
	s := &Server{}
	for _, storage := range []ikeStorage{ikeAttemptOnly, ikeWindowsStorage, 99} {
		p := []byte("sentinel")
		r := s.answerIKEAuth(context.Background(), ikeBinding{}, ikePassword, storage, ikeSecrets{p, p})
		if r.accepted || !bytes.Equal(p, make([]byte, len(p))) {
			t.Fatal("rejection clearing")
		}
	}
}

type authEngine struct {
	fakeEngine
	id string
}

func (e *authEngine) Status() core.Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return core.Status{State: e.state, Session: &core.SessionInfo{ID: e.id}}
}
func authFixture(t *testing.T) (*Server, *authEngine, context.CancelFunc) {
	t.Helper()
	e := &authEngine{fakeEngine: fakeEngine{state: core.Connecting}, id: "session"}
	s := NewServer(e)
	s.installation, s.instance = "installation", "instance"
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.bindForegroundSession(ctx, core.SessionConfig{IKEv2: &core.IKEv2Config{WindowsProfile: "profile", ServerName: "vpn.example.com"}})
	return s, e, cancel
}
func TestIKEAuthLifecycle(t *testing.T) {
	for _, action := range []string{"profile", "session", "stop", "invalid_stop", "close", "invalid_close", "cancel", "rebind"} {
		t.Run(action, func(t *testing.T) {
			s, e, cancel := authFixture(t)
			ctx, retire := s.ikeAuthority(context.Background())
			defer retire()
			b := ikeBinding{"installation", "instance", "session", "attempt", "request", "profile", "vpn.example.com"}
			if !s.beginIKEAuth(ctx, b, time.Minute, func([]byte, []byte) {}) {
				t.Fatal("begin")
			}
			r := Request{Version: Version, ID: "x", Installation: s.installation, Instance: s.instance, Session: e.id}
			valid := false
			switch action {
			case "profile":
				b.profile = "other"
			case "session":
				e.id = "replacement"
			case "stop":
				r.Command = "stop"
				s.foregroundDispatch(context.Background(), r)
			case "invalid_stop":
				r.Command = "stop"
				r.Instance = "stale"
				s.foregroundDispatch(context.Background(), r)
				valid = true
			case "close":
				e.state = core.Disconnected
				r.Command = "close_owner"
				if !s.foregroundDispatch(context.Background(), r).closeAccepted {
					t.Fatal("close rejected")
				}
				e.state = core.Connecting
			case "invalid_close":
				r.Command = "close_owner"
				s.foregroundDispatch(context.Background(), r)
				valid = true
			case "cancel":
				cancel()
			case "rebind":
				s.bindForegroundSession(context.Background(), core.SessionConfig{IKEv2: &core.IKEv2Config{WindowsProfile: "profile", ServerName: "vpn.example.com"}})
			}
			if got := s.answerIKEAuth(ctx, b, ikePassword, ikeAttemptOnly, ikeSecrets{[]byte("u"), []byte("p")}); got.accepted != valid {
				t.Fatal("unexpected acceptance")
			}
			if action == "rebind" {
				fresh, end := s.ikeAuthority(context.Background())
				defer end()
				if !s.beginIKEAuth(fresh, b, time.Minute, func([]byte, []byte) {}) {
					t.Fatal("fresh generation rejected")
				}
			}
		})
	}
}
