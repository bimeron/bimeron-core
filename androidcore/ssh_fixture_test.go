package androidcore

import (
	"bimeron/internal/accesskey"
	"bimeron/internal/sshtunnel"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthSSHFixture(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	for _, mode := range []string{"password", "key_passphrase", "keyboard_interactive", "cancel", "disconnect", "parent_deadline"} {
		t.Run(mode, func(t *testing.T) {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			signer, _ := ssh.NewSignerFromKey(key)
			cfg := &ssh.ServerConfig{}
			cfg.PasswordCallback = func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
				if string(p) != "secret" {
					return nil, fmt.Errorf("rejected")
				}
				return nil, nil
			}
			cfg.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, c ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
				a, e := c("", "", []string{"Code"}, []bool{false})
				if e != nil {
					return nil, e
				}
				if len(a) != 1 || a[0] != "secret" {
					return nil, fmt.Errorf("rejected")
				}
				return nil, nil
			}
			if mode == "keyboard_interactive" {
				cfg.PasswordCallback = nil
			}
			cfg.AddHostKey(signer)
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, e := l.Accept()
				if e != nil {
					return
				}
				accepted <- conn
				defer conn.Close()
				c, ch, r, e := ssh.NewServerConn(conn, cfg)
				if e != nil {
					return
				}
				defer c.Close()
				go ssh.DiscardRequests(r)
				for v := range ch {
					v.Reject(ssh.Prohibited, "fixture")
				}
			}()
			dir := t.TempDir()
			hosts := filepath.Join(dir, "known_hosts")
			if e := os.WriteFile(hosts, []byte(knownhosts.Line([]string{l.Addr().String()}, signer.PublicKey())+"\n"), 0600); e != nil {
				t.Fatal(e)
			}
			p, e := accesskey.ParseSSH("ssh://fixture@" + l.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			p.SSH.KnownHostsFile = hosts
			if mode == "key_passphrase" {
				_, user, _ := ed25519.GenerateKey(rand.Reader)
				us, _ := ssh.NewSignerFromKey(user)
				cfg.PublicKeyCallback = func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
					if string(k.Marshal()) != string(us.PublicKey().Marshal()) {
						return nil, fmt.Errorf("rejected")
					}
					return nil, nil
				}
				block, e := ssh.MarshalPrivateKeyWithPassphrase(user, "fixture", []byte("secret"))
				if e != nil {
					t.Fatal(e)
				}
				p.SSH.IdentityFile = filepath.Join(dir, "identity")
				if e = os.WriteFile(p.SSH.IdentityFile, pem.EncodeToMemory(block), 0600); e != nil {
					t.Fatal(e)
				}
			}
			s := &Session{}
			s.auth.id = opaqueID()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				client, e := sshtunnel.New(ctx, p, net.Dialer{}, s.auth.prompt(0), false)
				if client != nil {
					client.Close()
				}
				done <- e
			}()
			r := pending(t, s)
			switch mode {
			case "cancel":
				s.CancelAuth(r.SessionID, r.RequestID)
			case "disconnect":
				(<-accepted).Close()
			case "parent_deadline":
				cancel()
			default:
				if r.Kind != mode {
					t.Fatalf("kind %s", r.Kind)
				}
				if e := s.ReplyAuth(r.SessionID, r.RequestID, `["secret"]`); e != nil {
					t.Fatal(e)
				}
			}
			select {
			case e := <-done:
				wantFail := mode == "cancel" || mode == "disconnect" || mode == "parent_deadline"
				if (e != nil) != wantFail {
					t.Fatalf("result %v", e)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("handshake blocked")
			}
			if s.PendingAuth() != "null" {
				t.Fatal("terminal prompt remains")
			}
		})
	}
}
