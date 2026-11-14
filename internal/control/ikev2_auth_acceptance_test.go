package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func authBinding() ikeBinding {
	return ikeBinding{"installation", "instance", "session", "attempt", "request", "profile", "vpn.example.com"}
}
func checkedAnswer(t *testing.T, s *Server, ctx context.Context, b ikeBinding, i ikeIntent, st ikeStorage, u, p []byte) bool {
	t.Helper()
	got := s.answerIKEAuth(ctx, b, i, st, ikeSecrets{u, p})
	if !bytes.Equal(u, make([]byte, len(u))) || !bytes.Equal(p, make([]byte, len(p))) {
		t.Error("buffers not cleared")
	}
	return got.accepted
}
func TestIKEAuthMatrix(t *testing.T) {
	for field := 0; field < 7; field++ {
		t.Run(fmt.Sprint("binding", field), func(t *testing.T) {
			s, _, _ := authFixture(t)
			ctx, end := s.ikeAuthority(context.Background())
			defer end()
			b := authBinding()
			calls := 0
			if !s.beginIKEAuth(ctx, b, time.Minute, func([]byte, []byte) { calls++ }) {
				t.Fatal("begin")
			}
			bad := b
			fields := []*string{&bad.installation, &bad.instance, &bad.session, &bad.attempt, &bad.request, &bad.profile, &bad.server}
			*fields[field] = "wrong"
			if checkedAnswer(t, s, ctx, bad, ikePassword, ikeAttemptOnly, []byte("u"), []byte("p")) || calls != 0 {
				t.Fatal("mismatch dispatched")
			}
		})
	}
	for _, v := range []string{"", "\x00", "\xff", strings.Repeat("x", 257)} {
		t.Run(fmt.Sprintf("identifier-%x", v[:min(len(v), 2)]), func(t *testing.T) {
			for field := 0; field < 7; field++ {
				s, _, _ := authFixture(t)
				ctx, end := s.ikeAuthority(context.Background())
				b := authBinding()
				fields := []*string{&b.installation, &b.instance, &b.session, &b.attempt, &b.request, &b.profile, &b.server}
				*fields[field] = v
				if s.beginIKEAuth(ctx, b, time.Minute, func([]byte, []byte) {}) {
					t.Error("invalid identifier")
				}
				end()
			}
		})
	}
	for _, v := range []string{"", "\x00", "\xff", strings.Repeat("x", 1025)} {
		for field := 0; field < 2; field++ {
			t.Run(fmt.Sprintf("secret-%d-%x", field, v[:min(len(v), 2)]), func(t *testing.T) {
				s, _, _ := authFixture(t)
				ctx, end := s.ikeAuthority(context.Background())
				defer end()
				b := authBinding()
				calls := 0
				s.beginIKEAuth(ctx, b, time.Minute, func([]byte, []byte) { calls++ })
				u, p := []byte("u"), []byte("p")
				if field == 0 {
					u = []byte(v)
				} else {
					p = []byte(v)
				}
				if checkedAnswer(t, s, ctx, b, ikePassword, ikeAttemptOnly, u, p) || calls != 0 {
					t.Fatal("invalid secret")
				}
				if !checkedAnswer(t, s, ctx, b, ikePassword, ikeAttemptOnly, []byte("u"), []byte("p")) {
					t.Fatal("rejection consumed request")
				}
			})
		}
	}
	for _, tc := range []struct {
		i ikeIntent
		s ikeStorage
	}{{ikeCertificate, 0}, {ikeSmartCard, 0}, {99, 0}, {0, ikeWindowsStorage}, {0, 99}} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			s, _, _ := authFixture(t)
			ctx, end := s.ikeAuthority(context.Background())
			defer end()
			b := authBinding()
			calls := 0
			s.beginIKEAuth(ctx, b, time.Minute, func([]byte, []byte) { calls++ })
			alias := []byte("sentinel")
			if checkedAnswer(t, s, ctx, b, tc.i, tc.s, alias, alias) || calls != 0 {
				t.Fatal("unsupported dispatched")
			}
			if !checkedAnswer(t, s, ctx, b, 0, 0, []byte("u"), []byte("p")) {
				t.Fatal("consumed")
			}
		})
	}
}
func TestIKEAuthBoundsAndDeadline(t *testing.T) {
	s, _, _ := authFixture(t)
	ctx, end := s.ikeAuthority(context.Background())
	defer end()
	b := authBinding()
	b.attempt = strings.Repeat("a", 256)
	b.request = strings.Repeat("r", 256)
	for _, ttl := range []time.Duration{0, -1, 2*time.Minute + 1} {
		if s.beginIKEAuth(ctx, b, ttl, func([]byte, []byte) {}) {
			t.Fatal("ttl")
		}
	}
	if !s.beginIKEAuth(ctx, b, 2*time.Minute, func([]byte, []byte) {}) {
		t.Fatal("bounds")
	}
	alias := bytes.Repeat([]byte("x"), 1024)
	if !checkedAnswer(t, s, ctx, b, 0, 0, alias, alias) {
		t.Fatal("secret bound")
	}
	ctx2, end2 := s.ikeAuthority(context.Background())
	defer end2()
	s.beginIKEAuth(ctx2, b, time.Minute, func([]byte, []byte) { t.Error("expired dispatch") })
	s.ikeMu.Lock()
	s.ikePending.deadline = time.Now()
	s.ikeMu.Unlock()
	if checkedAnswer(t, s, ctx2, b, 0, 0, []byte("u"), []byte("p")) {
		t.Fatal("deadline")
	}
	ctx3, end3 := s.ikeAuthority(context.Background())
	defer end3()
	s.beginIKEAuth(ctx3, b, time.Millisecond, func([]byte, []byte) {})
	limit := time.Now().Add(time.Second)
	for {
		s.ikeMu.Lock()
		pending := s.ikePending != nil
		s.ikeMu.Unlock()
		if !pending {
			break
		}
		if time.Now().After(limit) {
			t.Fatal("timer did not retire")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestIKEAuthConcurrentRetirement(t *testing.T) {
	for _, action := range []string{"retire", "stop", "expiry"} {
		t.Run(action, func(t *testing.T) {
			for n := 0; n < 30; n++ {
				s, _, _ := authFixture(t)
				ctx, end := s.ikeAuthority(context.Background())
				b := authBinding()
				calls := 0
				s.beginIKEAuth(ctx, b, time.Minute, func([]byte, []byte) { calls++ })
				var wg sync.WaitGroup
				wg.Add(3)
				for i := 0; i < 2; i++ {
					go func() { defer wg.Done(); checkedAnswer(t, s, ctx, b, 0, 0, []byte("u"), []byte("p")) }()
				}
				go func() {
					defer wg.Done()
					switch action {
					case "retire":
						end()
					case "stop":
						s.disableIKEAuth()
					case "expiry":
						s.ikeMu.Lock()
						if s.ikePending != nil {
							s.ikePending.deadline = time.Now()
							s.retireIKEAuthLocked(s.ikePending)
						}
						s.ikeMu.Unlock()
					}
				}()
				wg.Wait()
				end()
				if calls > 1 {
					t.Fatal("multiple dispatch")
				}
			}
		})
	}
}
func TestIKESecretsDiagnostics(t *testing.T) {
	secret := ikeSecrets{[]byte("private-sentinel"), []byte("private-sentinel")}
	//lint:ignore SA9005 asserts secrets never serialize.
	data, _ := json.Marshal(secret)
	for _, v := range []string{fmt.Sprintf("%v", secret), fmt.Sprintf("%+v", secret), fmt.Sprintf("%#v", secret), string(data)} {
		if strings.Contains(v, "private-sentinel") {
			t.Fatal("secret leaked")
		}
	}
}

func TestIKEAuthAuthorityGuards(t *testing.T) {
	s, _, _ := authFixture(t)
	b := authBinding()
	ctx, end := s.ikeAuthority(context.Background())
	defer end()
	other, _, _ := authFixture(t)
	other.ikeMu.Lock()
	other.ikeOwner = nil
	other.ikeMu.Unlock()
	if other.beginIKEAuth(ctx, b, time.Minute, func([]byte, []byte) {}) || other.ikeDisabled {
		t.Fatal("foreign authority changed lifecycle")
	}
	if checkedAnswer(t, other, ctx, b, 0, 0, []byte("u"), []byte("p")) {
		t.Fatal("foreign answer")
	}
	if s.beginIKEAuth(context.Background(), b, time.Minute, func([]byte, []byte) {}) {
		t.Fatal("missing authority")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	dead, retire := s.ikeAuthority(cancelled)
	defer retire()
	if s.beginIKEAuth(dead, b, time.Minute, func([]byte, []byte) {}) {
		t.Fatal("cancelled")
	}
	if !s.beginIKEAuth(ctx, b, time.Minute, func([]byte, []byte) {}) {
		t.Fatal("begin")
	}
	second, end2 := s.ikeAuthority(context.Background())
	defer end2()
	if s.beginIKEAuth(second, b, time.Minute, func([]byte, []byte) {}) {
		t.Fatal("second pending")
	}
	end()
	if checkedAnswer(t, s, ctx, b, 0, 0, []byte("u"), []byte("p")) {
		t.Fatal("dead")
	}
}

func TestIKEAuthCancelledAnswerAndProduction(t *testing.T) {
	for _, mode := range []string{"production", "before-answer", "after-answer"} {
		t.Run(mode, func(t *testing.T) {
			s, _, _ := authFixture(t)
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx, end := s.ikeAuthority(base)
			defer end()
			b := authBinding()
			calls := 0
			if mode != "production" {
				s.beginIKEAuth(ctx, b, time.Minute, func([]byte, []byte) { calls++ })
			}
			if mode == "before-answer" {
				cancel()
			}
			accepted := checkedAnswer(t, s, ctx, b, 0, 0, []byte("u"), []byte("p"))
			if accepted != (mode == "after-answer") {
				t.Fatal("acceptance")
			}
			cancel()
			if checkedAnswer(t, s, ctx, b, 0, 0, []byte("u"), []byte("p")) || calls > 1 {
				t.Fatal("late answer")
			}
		})
	}
	for _, v := range []string{strings.Repeat("x", 256), strings.Repeat("é", 128)} {
		if !validIKEField(v) {
			t.Fatal("exact identifier byte bound")
		}
	}
	s, _, _ := authFixture(t)
	for _, command := range []string{"status", "events"} {
		r := s.foregroundDispatch(context.Background(), Request{Version: Version, ID: "x", Command: command, Installation: "installation", Instance: "instance", Session: "session"})
		data, _ := json.Marshal(r)
		if strings.Contains(string(data), "private-sentinel") {
			t.Fatal("snapshot leak")
		}
	}
}
