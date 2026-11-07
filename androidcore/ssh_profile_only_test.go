package androidcore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/sshtunnel"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// publicKeyFixture accepts only user key on a fresh host key.
func publicKeyFixture(t *testing.T, user ssh.PublicKey) (string, ssh.Signer) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	host, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) != string(user.Marshal()) {
			return nil, errors.New("rejected")
		}
		return nil, nil
	}}
	cfg.AddHostKey(host)
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
	return l.Addr().String(), host
}

type fileTrace struct {
	mu  sync.Mutex
	ops []string
}

func (f *fileTrace) record(op, path string) {
	f.mu.Lock()
	f.ops = append(f.ops, op+" "+path)
	f.mu.Unlock()
}

func (f *fileTrace) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ops...)
}

// Decision 8: an Android Session never reads $HOME/.ssh, even when it holds
// the only key and known_hosts that would make the connection succeed.
func TestAndroidSSHIgnoresHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(home, "agent.sock"))
	_, userKey, _ := ed25519.GenerateKey(rand.Reader)
	userSigner, _ := ssh.NewSignerFromKey(userKey)
	address, host := publicKeyFixture(t, userSigner.PublicKey())
	block, _ := ssh.MarshalPrivateKey(userKey, "")
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(knownhosts.Line([]string{address}, host.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Control: the non-Android default path connects using exactly these files.
	t.Setenv("SSH_AUTH_SOCK", "")
	control := &fileTrace{}
	restore := sshtunnel.SetFileTrace(control.record)
	p, _ := accesskey.ParseSSH("ssh://fixture@" + address)
	c, err := sshtunnel.New(context.Background(), p, net.Dialer{}, nil, true)
	restore()
	if err != nil || !strings.Contains(strings.Join(control.list(), "\n"), filepath.Join(dir, "id_ed25519")) {
		t.Fatalf("control %v %v", err, control.list())
	}
	c.Close()
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(home, "agent.sock"))
	// Lock the fake ~/.ssh so that any real access the trace misses fails
	// instead of silently succeeding. Windows and root ignore the mode.
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	if _, err := os.ReadFile(filepath.Join(dir, "known_hosts")); err == nil && runtime.GOOS != "windows" && os.Geteuid() != 0 {
		t.Fatal("fake ~/.ssh is still readable")
	}

	base := "[Profile]\nVersion = 1\n[AccessKey]\nSSH = ssh://fixture@" + address + "\n"
	for _, tc := range []struct {
		name, profile string
		optIn         bool
		want          string
	}{
		{"no_known_hosts", base, false, sshtunnel.KnownHostsMissing},
		{"accept_new_without_home_key", base, true, "ssh_connection_failed"},
		{"home_relative_paths", base + "IdentityFile = ~/.ssh/id_ed25519\nKnownHostsFile = ~/.ssh/known_hosts\n", false, "ssh_connection_failed"},
		{"home_relative_identity", base + "IdentityFile = ~/.ssh/id_ed25519\n", true, "ssh_connection_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trace := &fileTrace{}
			defer sshtunnel.SetFileTrace(trace.record)()
			s, err := NewSession([]byte(tc.profile), &testProtector{allow: true})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Stop()
			if s.config.SSHDefaultKeys || !s.config.SSHProfileOnly {
				t.Fatal("Android SSH guard missing")
			}
			if tc.optIn {
				if err := s.AcceptNewHostKeys(nil); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.SetNetwork("wifi", "192.0.2.53"); err != nil {
				t.Fatal(err)
			}
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
			if tc.name == "accept_new_without_home_key" {
				// The home known_hosts trusts this host; an offer proves it was not read.
				rawPending(t, s)
				r := pending(t, s)
				if r.Kind != sshtunnel.HostKeyKind || s.ReplyAuth(r.SessionID, r.RequestID, `["accept"]`) != nil {
					t.Fatalf("offer %+v", r)
				}
			}
			if got := waitFailed(t, s); got != tc.want {
				t.Fatalf("lastError %q want %q", got, tc.want)
			}
			if s.PendingAuth() != "null" {
				t.Fatal("unexpected prompt")
			}
			for _, op := range trace.list() {
				if strings.HasPrefix(op, "home") || strings.HasPrefix(op, "agent") || strings.Contains(op, home) {
					t.Fatalf("touched %q", op)
				}
			}
		})
	}
}

// Once ReplyAuth has accepted an answer, the prompt returns it even if its
// context ends at the same moment: ReplyAuth and cancel are released together
// from a shared barrier, and the prompt result must agree with ReplyAuth.
func TestAuthReplyWinsOverDeadline(t *testing.T) {
	line := knownhosts.Line([]string{"example.com:22"}, otherKey(t))
	offer := sshtunnel.HostKeyOffer{Host: "example.com:22", KeyType: "ssh-ed25519", Fingerprint: "SHA256:" + strings.Repeat("A", 43), KnownHostsLine: line}
	accepted := 0
	const rounds = 500
	for i := 0; i < rounds; i++ {
		s := &Session{}
		s.auth.id = opaqueID()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			answers, err := s.auth.prompt(0)(ctx, sshtunnel.Challenge{Kind: sshtunnel.HostKeyKind, HostKey: &offer})
			if err == nil && (len(answers) != 1 || answers[0] != sshtunnel.HostKeyAccept) {
				err = errors.New("wrong answers")
			}
			done <- err
		}()
		r := pending(t, s)
		barrier := make(chan struct{})
		var race sync.WaitGroup
		var replied error
		race.Add(2)
		go func() { defer race.Done(); <-barrier; replied = s.ReplyAuth(r.SessionID, r.RequestID, `["accept"]`) }()
		go func() {
			defer race.Done()
			<-barrier
			// Sweep the cancel across ReplyAuth's whole critical section.
			for j := 0; j < i%64; j++ {
				runtime.Gosched()
			}
			cancel()
		}()
		close(barrier)
		race.Wait()
		if err := <-done; (replied == nil) != (err == nil) {
			t.Fatalf("round %d: reply %v, prompt %v", i, replied, err)
		}
		if replied == nil {
			accepted++
		}
	}
	t.Logf("ReplyAuth won %d of %d races", accepted, rounds)
	// A reply after the deadline fails and the prompt is unanswered.
	s := &Session{}
	s.auth.id = opaqueID()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := s.auth.prompt(0)(ctx, sshtunnel.Challenge{Kind: sshtunnel.HostKeyKind, HostKey: &offer})
		done <- err
	}()
	r := pending(t, s)
	<-ctx.Done()
	if err := <-done; err == nil || s.ReplyAuth(r.SessionID, r.RequestID, `["accept"]`) == nil {
		t.Fatal("late reply accepted")
	}
}
