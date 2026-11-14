package control

import (
	"bimeron/core"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func authWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("bounded completion timed out")
	}
}

func TestIKEAuthBlockedResponseCancellation(t *testing.T) {
	for _, peerClose := range []bool{false, true} {
		t.Run(fmt.Sprint(peerClose), func(t *testing.T) {
			s, _, _ := authFixture(t)
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			dispatched := make(chan struct{})
			done := make(chan struct{})
			var ctx context.Context
			original := s.foregroundDispatch
			s.foregroundDispatch = func(c context.Context, r Request) Response {
				ctx = c
				if !s.beginIKEAuth(c, authBinding(), time.Minute, func([]byte, []byte) { t.Error("unexpected consume") }) {
					t.Error("begin")
				}
				response := original(c, r)
				close(dispatched)
				return response
			}
			s.authorize = func(net.Conn) (func(), error) { return func() {}, nil }
			server, client := net.Pipe()
			defer client.Close()
			defer server.Close()
			client.SetWriteDeadline(time.Now().Add(time.Second))
			go func() { defer close(done); s.handle(base, server) }()
			if _, err := client.Write([]byte("{\"version\":1,\"command\":\"hello\",\"installation\":\"installation\"}\n")); err != nil {
				t.Fatal(err)
			}
			authWait(t, dispatched)
			select {
			case <-done:
				t.Fatal("response unexpectedly completed without reader")
			default:
			}
			if peerClose {
				client.Close()
			} else {
				cancel()
			}
			authWait(t, done)
			a := ctx.Value(ikeAuthorityKey{}).(*ikeAuth)
			s.ikeMu.Lock()
			bad := a.live || a.consume != nil || s.ikePending != nil || s.ikeOwner.Err() != nil
			s.ikeMu.Unlock()
			if bad {
				t.Fatal("exchange retirement affected owner or retained authority")
			}
			if checkedAnswer(t, s, ctx, authBinding(), 0, 0, []byte("u"), []byte("p")) {
				t.Fatal("late accepted")
			}
		})
	}
}

func TestIKEAuthDispatchStopAndTimerRace(t *testing.T) {
	for _, mode := range []string{"stop", "timer"} {
		t.Run(mode, func(t *testing.T) {
			for n := 0; n < 10; n++ {
				s, _, _ := authFixture(t)
				ctx, end := s.ikeAuthority(context.Background())
				defer end()
				b := authBinding()
				calls := 0
				ttl := time.Minute
				if mode == "timer" {
					ttl = 2 * time.Millisecond
				}
				if !s.beginIKEAuth(ctx, b, ttl, func([]byte, []byte) { calls++ }) {
					t.Fatal("begin")
				}
				start := make(chan struct{})
				results := make(chan bool, 2)
				for i := 0; i < 2; i++ {
					go func() {
						<-start
						if mode == "timer" {
							time.Sleep(ttl)
						}
						results <- checkedAnswer(t, s, ctx, b, 0, 0, []byte("u"), []byte("p"))
					}()
				}
				stopped := make(chan Response, 1)
				if mode == "stop" {
					go func() {
						<-start
						stopped <- s.foregroundDispatch(context.Background(), Request{Version: Version, ID: "fixture", Command: "stop", Installation: b.installation, Instance: b.instance, Session: b.session})
					}()
				}
				close(start)
				for i := 0; i < 2; i++ {
					select {
					case <-results:
					case <-time.After(time.Second):
						t.Fatal("answer timeout")
					}
				}
				if mode == "stop" {
					select {
					case r := <-stopped:
						if r.Error != "" {
							t.Fatal(r.Error)
						}
					case <-time.After(time.Second):
						t.Fatal("stop timeout")
					}
				}
				deadline := time.Now().Add(time.Second)
				for {
					s.ikeMu.Lock()
					pending := s.ikePending != nil
					bad := calls > 1
					s.ikeMu.Unlock()
					if bad {
						t.Fatal("multiple consumers")
					}
					if !pending {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("pending timeout")
					}
					time.Sleep(time.Millisecond)
				}
				if checkedAnswer(t, s, ctx, b, 0, 0, []byte("u"), []byte("p")) {
					t.Fatal("late accepted")
				}
				s.ikeMu.Lock()
				retained := ctx.Value(ikeAuthorityKey{}).(*ikeAuth).consume != nil
				s.ikeMu.Unlock()
				if retained {
					t.Fatal("retained consumer")
				}
			}
		})
	}
}

func TestIKEAuthFullBoundsDiagnostics(t *testing.T) {
	s, e, _ := authFixture(t)
	b := authBinding()
	b.installation = strings.Repeat("i", 256)
	b.instance = strings.Repeat("o", 256)
	b.session = strings.Repeat("s", 256)
	b.attempt = strings.Repeat("a", 256)
	b.request = strings.Repeat("r", 256)
	b.profile = strings.Repeat("p", 256)
	b.server = strings.Repeat("d", 63) + "." + strings.Repeat("e", 63) + "." + strings.Repeat("f", 63) + "." + strings.Repeat("g", 61)
	s.installation = b.installation
	s.instance = b.instance
	e.id = b.session
	cfg := core.SessionConfig{IKEv2: &core.IKEv2Config{WindowsProfile: b.profile, ServerName: b.server}}
	//lint:ignore SA1026 asserts secrets never leak through serialization.
	before, _ := json.Marshal(cfg)
	s.bindForegroundSession(context.Background(), cfg)
	cfg.IKEv2.WindowsProfile = "mutated"
	cfg.IKEv2.ServerName = "changed.example"
	ctx, end := s.ikeAuthority(context.Background())
	defer end()
	if s.beginIKEAuth(ctx, b, time.Minute, nil) {
		t.Fatal("nil consumer accepted")
	}
	sentinel := "synthetic-private-secret"
	calls := 0
	if !s.beginIKEAuth(ctx, b, time.Minute, func(u, p []byte) {
		calls++
		if !bytes.Equal(u, []byte(sentinel)) || !bytes.Equal(p, []byte(sentinel)) {
			t.Error("consumer bytes")
		}
	}) {
		t.Fatal("full bounds or immutable copy")
	}
	for _, storage := range []ikeStorage{ikeWindowsStorage, ikeAttemptOnly} {
		secret := ikeSecrets{[]byte(sentinel), []byte(sentinel)}
		diagnostics := fmt.Sprintf("%v %+v %#v", secret, secret, secret)
		//lint:ignore SA9005 asserts secrets never leak through serialization.
		data, err := json.Marshal(secret)
		diagnostics += string(data) + fmt.Sprint(err)
		result := s.answerIKEAuth(ctx, b, ikePassword, storage, secret)
		if result.accepted != (storage == ikeAttemptOnly) || result.storage != map[ikeStorage]string{ikeWindowsStorage: "unsupported", ikeAttemptOnly: "not_requested"}[storage] {
			t.Fatal("storage result")
		}
		if !bytes.Equal(secret.username, make([]byte, len(secret.username))) || !bytes.Equal(secret.password, make([]byte, len(secret.password))) {
			t.Fatal("secret clearing")
		}
		//lint:ignore SA9005 asserts secrets never leak through serialization.
		data, err = json.Marshal(result)
		diagnostics += string(data) + fmt.Sprint(result, err)
		for _, command := range []string{"status", "events"} {
			r := s.foregroundDispatch(context.Background(), Request{Version: Version, ID: "fixture", Command: command, Installation: b.installation, Instance: b.instance, Session: b.session})
			data, err = json.Marshal(r)
			diagnostics += string(data) + fmt.Sprint(r.Error, err)
		}
		//lint:ignore SA1026 asserts secrets never leak through serialization.
		data, err = json.Marshal(cfg)
		diagnostics += string(data) + fmt.Sprint(err)
		if strings.Contains(diagnostics, sentinel) {
			t.Fatal("diagnostic leak")
		}
	}
	if calls != 1 {
		t.Fatal("consumer count")
	}
	cfg.IKEv2.WindowsProfile = b.profile
	cfg.IKEv2.ServerName = b.server
	//lint:ignore SA1026 asserts secrets never leak through serialization.
	after, _ := json.Marshal(cfg)
	if !bytes.Equal(before, after) {
		t.Fatal("config changed")
	}
	s.bindForegroundSession(context.Background(), core.SessionConfig{})
	fresh, retire := s.ikeAuthority(context.Background())
	defer retire()
	if s.beginIKEAuth(fresh, b, time.Minute, func([]byte, []byte) {}) {
		t.Fatal("missing launch config accepted")
	}
}
