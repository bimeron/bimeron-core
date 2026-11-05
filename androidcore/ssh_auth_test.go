package androidcore

import (
	"bimeron/internal/sshtunnel"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func pending(t *testing.T, s *Session) authRequest {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		var r authRequest
		if json.Unmarshal([]byte(s.PendingAuth()), &r) == nil && r.RequestID != "" {
			return r
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("missing prompt")
	return authRequest{}
}
func TestAuthLifecycle(t *testing.T) {
	for _, mode := range []string{"reply", "cancel", "network", "stop", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			s := &Session{}
			s.auth.id = opaqueID()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := s.auth.prompt(0)(ctx, sshtunnel.Challenge{Kind: "password", Prompts: []string{"Password"}, Echo: []bool{false}})
				done <- err
			}()
			r := pending(t, s)
			if s.ReplyAuth("wrong", r.RequestID, `["secret"]`) == nil {
				t.Fatal("wrong session accepted")
			}
			switch mode {
			case "reply":
				if err := s.ReplyAuth(r.SessionID, r.RequestID, `["secret"]`); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				if err := s.CancelAuth(r.SessionID, r.RequestID); err != nil {
					t.Fatal(err)
				}
			case "network":
				s.auth.invalidate(1, false)
			case "stop":
				s.auth.invalidate(0, true)
			case "deadline":
				cancel()
			}
			select {
			case err := <-done:
				if (err == nil) != (mode == "reply") {
					t.Fatalf("unexpected result %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("blocked")
			}
			if s.PendingAuth() != "null" || s.ReplyAuth(r.SessionID, r.RequestID, `["secret"]`) == nil || s.CancelAuth(r.SessionID, r.RequestID) == nil {
				t.Fatal("stale request accepted")
			}
		})
	}
}
func TestAuthBounds(t *testing.T) {
	for _, p := range []string{strings.Repeat("x", 1025), "bad\n", "bad\u202e", string([]byte{255}), strings.Repeat("<", 1024)} {
		s := &Session{}
		s.auth.id = opaqueID()
		prompts := []string{p}
		echo := []bool{false}
		if strings.HasPrefix(p, "<") {
			for len(prompts) < 8 {
				prompts = append(prompts, p)
				echo = append(echo, false)
			}
		}
		if _, err := s.auth.prompt(0)(context.Background(), sshtunnel.Challenge{Kind: "password", Prompts: prompts, Echo: echo}); err == nil {
			t.Fatal("invalid prompt accepted")
		}
	}
	s := &Session{}
	s.auth.invalidate(1, false)
	if _, err := s.auth.prompt(0)(context.Background(), sshtunnel.Challenge{Kind: "password", Prompts: []string{"Password"}, Echo: []bool{false}}); err == nil {
		t.Fatal("stale generation published")
	}
}

func TestAuthConcurrentConsumption(t *testing.T) {
	s := &Session{}
	s.auth.id = opaqueID()
	done := make(chan error, 1)
	go func() {
		_, e := s.auth.prompt(0)(context.Background(), sshtunnel.Challenge{Kind: "password", Prompts: []string{"Password"}, Echo: []bool{false}})
		done <- e
	}()
	r := pending(t, s)
	results := make(chan error, 32)
	for i := 0; i < 32; i++ {
		go func() { results <- s.ReplyAuth(r.SessionID, r.RequestID, `["secret"]`) }()
	}
	successes := 0
	for i := 0; i < 32; i++ {
		if <-results == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("accepted %d", successes)
	}
	<-done
}

func TestAuthSessionHooks(t *testing.T) {
	for _, stop := range []bool{false, true} {
		s, e := NewSession([]byte(testProfile), &testProtector{allow: true})
		if e != nil {
			t.Fatal(e)
		}
		if e = s.SetNetwork("first", "1.1.1.1"); e != nil {
			t.Fatal(e)
		}
		path, e := s.outbound(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() {
			_, e := path.SSHPrompt(context.Background(), sshtunnel.Challenge{Kind: "password", Prompts: []string{"Password"}, Echo: []bool{false}})
			done <- e
		}()
		r := pending(t, s)
		if stop {
			e = s.Stop()
		} else {
			e = s.SetNetwork("second", "1.1.1.1")
		}
		if e != nil {
			t.Fatal(e)
		}
		if s.PendingAuth() != "null" || s.ReplyAuth(r.SessionID, r.RequestID, `["secret"]`) == nil {
			t.Fatal("hook retained request")
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("hook blocked")
		}
		if _, e = path.SSHPrompt(context.Background(), sshtunnel.Challenge{Kind: "password", Prompts: []string{"Password"}, Echo: []bool{false}}); e == nil {
			t.Fatal("stale path published")
		}
		s.Stop()
	}
}

func TestAuthStrictAnswers(t *testing.T) {
	for _, valid := range []string{`[""]`, `["\ud83d\ude00"]`, `["�"]`} {
		s := &Session{}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, e := s.auth.prompt(0)(ctx, sshtunnel.Challenge{Kind: "password", Prompts: []string{"Password"}, Echo: []bool{false}})
			done <- e
		}()
		r := pending(t, s)
		for _, bad := range []string{`[null]`, `[1]`, `["\ud800"]`, `["\udc00"]`, `["\ud800\u0041"]`, `["\ud800x"]`} {
			if s.ReplyAuth(r.SessionID, r.RequestID, bad) == nil || s.PendingAuth() == "null" {
				t.Fatal("invalid answer consumed request")
			}
		}
		if e := s.ReplyAuth(r.SessionID, r.RequestID, valid); e != nil {
			t.Fatal(e)
		}
		<-done
		cancel()
	}
}
