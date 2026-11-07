package androidcore

import (
	"bimeron/internal/accesskey"
	"bimeron/internal/sshtunnel"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyFixture serves password "secret" with a fresh Ed25519 host key.
func hostKeyFixture(t *testing.T) (string, ssh.Signer) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if string(p) != "secret" {
			return nil, fmt.Errorf("rejected")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				c, ch, r, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer c.Close()
				go ssh.DiscardRequests(r)
				for v := range ch {
					v.Reject(ssh.Prohibited, "fixture")
				}
			}()
		}
	}()
	return l.Addr().String(), signer
}

func otherKey(t *testing.T) ssh.PublicKey {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(key)
	return s.PublicKey()
}

// rawPending waits for a pending request and returns its exact wire bytes.
func rawPending(t *testing.T, s *Session) (string, map[string]any) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if wire := s.PendingAuth(); wire != "null" {
			var m map[string]any
			if err := json.Unmarshal([]byte(wire), &m); err != nil {
				t.Fatal(err)
			}
			return wire, m
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("missing prompt")
	return "", nil
}

func hostKeyCode(err error) string {
	var e *sshtunnel.HostKeyError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestAuthHostKeyOffer(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	address, signer := hostKeyFixture(t)
	line := knownhosts.Line([]string{address}, signer.PublicKey())
	for _, mode := range []string{"accept", "cancel", "parent_deadline", "network", "stop", "mismatch", "known"} {
		t.Run(mode, func(t *testing.T) {
			s := &Session{}
			s.auth.id = opaqueID()
			trusted := ""
			switch mode {
			case "mismatch":
				trusted = knownhosts.Line([]string{address}, otherKey(t))
			case "known":
				trusted = line
			}
			keys, err := sshtunnel.ParseHostKeys([]byte(trusted))
			if err != nil {
				t.Fatal(err)
			}
			p, _ := accesskey.ParseSSH("ssh://fixture@" + address)
			limit := 30 * time.Second
			if mode == "parent_deadline" {
				limit = 500 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), limit)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				c, err := sshtunnel.NewWithOptions(ctx, p, net.Dialer{}, s.auth.prompt(0), sshtunnel.Options{HostKeys: keys})
				if c != nil {
					c.Close()
				}
				done <- err
			}()
			if mode == "mismatch" || mode == "known" {
				// No host-key offer: a password prompt (known) or nothing (mismatch).
				var err error
				for {
					select {
					case err = <-done:
					case <-time.After(5 * time.Millisecond):
						if wire := s.PendingAuth(); wire != "null" {
							r := pending(t, s)
							if r.Kind != "password" {
								t.Fatalf("unexpected offer %s", wire)
							}
							if e := s.ReplyAuth(r.SessionID, r.RequestID, `["secret"]`); e != nil {
								t.Fatal(e)
							}
						}
						continue
					}
					break
				}
				if want := map[string]string{"mismatch": sshtunnel.HostKeyMismatch, "known": ""}[mode]; hostKeyCode(err) != want || (mode == "known") != (err == nil) {
					t.Fatalf("result %v", err)
				}
				return
			}
			wire, m := rawPending(t, s)
			r := pending(t, s)
			host, port, _ := net.SplitHostPort(address)
			want := fmt.Sprintf(`{"sessionId":"%s","requestId":"%s","kind":"host_key","host":"%s","keyType":"ssh-ed25519","fingerprint":"%s","knownHostsLine":"%s"}`,
				r.SessionID, r.RequestID, net.JoinHostPort(host, port), ssh.FingerprintSHA256(signer.PublicKey()), line)
			if wire != want || len(m) != 7 {
				t.Fatalf("wire\n%s\nwant\n%s", wire, want)
			}
			for _, bad := range []string{`["yes"]`, `["Accept"]`, `["accept","accept"]`, `[""]`, `[]`} {
				if s.ReplyAuth(r.SessionID, r.RequestID, bad) == nil || s.PendingAuth() == "null" {
					t.Fatalf("answer %s consumed offer", bad)
				}
			}
			switch mode {
			case "accept":
				if err := s.ReplyAuth(r.SessionID, r.RequestID, `["accept"]`); err != nil {
					t.Fatal(err)
				}
				pw := pending(t, s)
				for pw.RequestID == r.RequestID {
					pw = pending(t, s)
				}
				if pw.Kind != "password" {
					t.Fatalf("kind %s", pw.Kind)
				}
				if err := s.ReplyAuth(pw.SessionID, pw.RequestID, `["secret"]`); err != nil {
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
			}
			var result error
			select {
			case result = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("handshake blocked")
			}
			wantCode := map[string]string{"accept": "", "cancel": sshtunnel.HostKeyRejected, "parent_deadline": sshtunnel.HostKeyUnanswered, "network": sshtunnel.HostKeyUnanswered, "stop": sshtunnel.HostKeyUnanswered}[mode]
			if hostKeyCode(result) != wantCode || (mode == "accept") != (result == nil) {
				t.Fatalf("result %v", result)
			}
			if s.PendingAuth() != "null" || s.ReplyAuth(r.SessionID, r.RequestID, `["accept"]`) == nil {
				t.Fatal("stale offer accepted")
			}
		})
	}
}

// Existing kinds keep their exact wire bytes.
func TestAuthWireCompatibility(t *testing.T) {
	s := &Session{}
	s.auth.id = opaqueID()
	done := make(chan error, 1)
	go func() {
		_, err := s.auth.prompt(0)(context.Background(), sshtunnel.Challenge{Kind: "keyboard_interactive", Prompts: []string{"Code", "PIN"}, Echo: []bool{true, false}})
		done <- err
	}()
	wire, _ := rawPending(t, s)
	r := pending(t, s)
	want := `{"sessionId":"` + r.SessionID + `","requestId":"` + r.RequestID + `","kind":"keyboard_interactive","prompts":["Code","PIN"],"echo":[true,false]}`
	if wire != want {
		t.Fatalf("wire %s", wire)
	}
	if s.ReplyAuth(r.SessionID, r.RequestID, `["accept"]`) == nil {
		t.Fatal("host-key answer accepted for text prompt")
	}
	s.CancelAuth(r.SessionID, r.RequestID)
	if err := <-done; err == nil || errors.Is(err, sshtunnel.ErrHostKeyDeclined) {
		t.Fatalf("text cancel %v", err)
	}
}

func TestAuthHostKeyOfferBounds(t *testing.T) {
	line := knownhosts.Line([]string{"example.com:22"}, otherKey(t))
	ok := sshtunnel.HostKeyOffer{Host: "example.com:22", KeyType: "ssh-ed25519", Fingerprint: "SHA256:" + strings.Repeat("A", 43), KnownHostsLine: line}
	if !validOffer(&ok) {
		t.Fatal("valid offer rejected")
	}
	for _, mutate := range []func(*sshtunnel.HostKeyOffer){
		func(o *sshtunnel.HostKeyOffer) { o.Host = "bad\nhost:22" },
		func(o *sshtunnel.HostKeyOffer) { o.KeyType = "" },
		func(o *sshtunnel.HostKeyOffer) { o.KeyType = "ssh-rsa" },
		func(o *sshtunnel.HostKeyOffer) { o.Fingerprint = "MD5:aa" },
		func(o *sshtunnel.HostKeyOffer) { o.Fingerprint = "SHA256:" + strings.Repeat("A", 43) + "=" },
		func(o *sshtunnel.HostKeyOffer) { o.KnownHostsLine += " comment" },
		func(o *sshtunnel.HostKeyOffer) { o.KnownHostsLine += "\n" },
		func(o *sshtunnel.HostKeyOffer) { o.KnownHostsLine = strings.Repeat("a", 12289) },
		func(o *sshtunnel.HostKeyOffer) {
			o.KnownHostsLine = "other.example.com" + strings.TrimPrefix(o.KnownHostsLine, "example.com")
		},
		func(o *sshtunnel.HostKeyOffer) {
			o.KnownHostsLine = "[example.com]:22" + strings.TrimPrefix(o.KnownHostsLine, "example.com")
		},
		func(o *sshtunnel.HostKeyOffer) { o.Host = "Example.com:22" },
		func(o *sshtunnel.HostKeyOffer) { o.Host = "example.com:2222" },
	} {
		o := ok
		mutate(&o)
		s := &Session{}
		// A published offer would block until this deadline and then report
		// itself through PendingAuth having been non-null; fail fast instead.
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		published := make(chan bool, 1)
		go func() { published <- rawPendingWithin(s, ctx) }()
		_, err := s.auth.prompt(0)(ctx, sshtunnel.Challenge{Kind: sshtunnel.HostKeyKind, HostKey: &o})
		cancel()
		if err == nil || <-published {
			t.Fatalf("invalid offer published %+v", o)
		}
	}
	s := &Session{}
	if _, err := s.auth.prompt(0)(context.Background(), sshtunnel.Challenge{Kind: sshtunnel.HostKeyKind, HostKey: &ok, Prompts: []string{"x"}, Echo: []bool{false}}); err == nil {
		t.Fatal("host_key with prompts published")
	}
	if _, err := s.auth.prompt(0)(context.Background(), sshtunnel.Challenge{Kind: "password", Prompts: []string{"x"}, Echo: []bool{false}, HostKey: &ok}); err == nil {
		t.Fatal("text prompt with host key published")
	}
}

func TestAcceptNewHostKeysLifecycle(t *testing.T) {
	s, err := NewSession([]byte(testProfile), &testProtector{allow: true})
	if err != nil {
		t.Fatal(err)
	}
	if s.AcceptNewHostKeys([]byte("*.example.com ssh-ed25519 AAAA\n")) == nil || s.config.SSHHostKeys != nil {
		t.Fatal("invalid trusted keys accepted")
	}
	if err := s.AcceptNewHostKeys(nil); err != nil {
		t.Fatal(err)
	}
	if s.AcceptNewHostKeys(nil) == nil {
		t.Fatal("second call accepted")
	}
	s.Stop()
	s2, _ := NewSession([]byte(testProfile), &testProtector{allow: true})
	s2.Stop()
	if s2.AcceptNewHostKeys(nil) == nil {
		t.Fatal("call after Stop accepted")
	}
}

func waitFailed(t *testing.T, s *Session) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var v struct {
			Status struct{ State, LastError string }
		}
		json.Unmarshal([]byte(s.Status()), &v)
		if v.Status.State == "failed" {
			return v.Status.LastError
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("not failed: %s", s.Status())
	return ""
}

// The Session surfaces distinct host-key faults only after opting in.
func TestAcceptNewHostKeysFaults(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	address, _ := hostKeyFixture(t)
	changed := knownhosts.Line([]string{address}, otherKey(t))
	hosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(hosts, []byte(changed+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	profile := "[Profile]\nVersion = 1\n[AccessKey]\nSSH = ssh://fixture@" + address + "\nKnownHostsFile = " + hosts + "\n"
	for _, tc := range []struct {
		name    string
		optIn   bool
		trusted string
		profile string
		want    string
	}{
		{"legacy_changed", false, "", profile, "ssh_connection_failed"},
		{"imported_changed", true, "", profile, sshtunnel.HostKeyMismatch},
		{"trusted_changed", true, changed, "[Profile]\nVersion = 1\n[AccessKey]\nSSH = ssh://fixture@" + address + "\n", sshtunnel.HostKeyMismatch},
		{"unknown_cancelled", true, "", "[Profile]\nVersion = 1\n[AccessKey]\nSSH = ssh://fixture@" + address + "\n", sshtunnel.HostKeyRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewSession([]byte(tc.profile), &testProtector{allow: true})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Stop()
			if tc.optIn {
				if err := s.AcceptNewHostKeys([]byte(tc.trusted)); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.SetNetwork("wifi", "192.0.2.53"); err != nil {
				t.Fatal(err)
			}
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
			if tc.name == "unknown_cancelled" {
				rawPending(t, s)
				r := pending(t, s)
				if r.Kind != "host_key" || s.CancelAuth(r.SessionID, r.RequestID) != nil {
					t.Fatalf("offer %+v", r)
				}
			}
			if got := waitFailed(t, s); got != tc.want {
				t.Fatalf("lastError %q want %q", got, tc.want)
			}
		})
	}
}

// rawPendingWithin reports whether a request was published before ctx ends.
func rawPendingWithin(s *Session, ctx context.Context) bool {
	for ctx.Err() == nil {
		if s.PendingAuth() != "null" {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}
