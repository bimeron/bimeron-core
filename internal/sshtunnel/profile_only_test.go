package sshtunnel

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"bimeron/internal/accesskey"
	"golang.org/x/crypto/ssh/knownhosts"
)

type traced struct {
	mu  sync.Mutex
	ops []string
}

func (r *traced) record(op, path string) {
	r.mu.Lock()
	r.ops = append(r.ops, op+" "+path)
	r.mu.Unlock()
}
func (r *traced) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ops...)
}

// ProfileOnly never looks at the user home or an agent.
func TestProfileOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(home, "agent.sock"))
	server := hostSigner(t)
	address := hostKeyServer(t, server)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(knownhosts.Line([]string{address}, server.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	dial := func(o Options, identity, hosts string) ([]string, error) {
		r := &traced{}
		defer SetFileTrace(r.record)()
		p, _ := accesskey.ParseSSH("ssh://alice@" + address)
		p.SSH.IdentityFile, p.SSH.KnownHostsFile = identity, hosts
		c, err := NewWithOptions(context.Background(), p, net.Dialer{}, (&offers{}).prompt, o)
		if c != nil {
			c.Close()
		}
		return r.list(), err
	}
	// Control: without ProfileOnly the home known_hosts is used and traced.
	if ops, err := dial(Options{DefaultKeys: true}, "", ""); err != nil || !strings.Contains(strings.Join(ops, "\n"), home) {
		t.Fatalf("control %v %v", err, ops)
	}
	for name, tc := range map[string]struct {
		o              Options
		identity, file string
		code           string
	}{
		"missing":        {Options{ProfileOnly: true, DefaultKeys: true}, "", "", KnownHostsMissing},
		"home_hosts":     {Options{ProfileOnly: true, DefaultKeys: true}, "", "~/.ssh/known_hosts", "plain"},
		"home_identity":  {Options{ProfileOnly: true, HostKeys: mustKeys(t, "")}, "~/.ssh/id_ed25519", "", "plain"},
		"accept_new":     {Options{ProfileOnly: true, DefaultKeys: true, HostKeys: mustKeys(t, "")}, "", "", ""},
		"selected_hosts": {Options{ProfileOnly: true, DefaultKeys: true}, "", writeHosts(t, knownhosts.Line([]string{address}, server.PublicKey())), ""},
	} {
		t.Run(name, func(t *testing.T) {
			ops, err := dial(tc.o, tc.identity, tc.file)
			for _, op := range ops {
				if strings.HasPrefix(op, "home") || strings.HasPrefix(op, "agent") || strings.Contains(op, home) {
					t.Fatalf("touched %q", op)
				}
			}
			switch tc.code {
			case "":
				if err != nil {
					t.Fatal(err)
				}
			case "plain":
				if err == nil || code(err) != "" {
					t.Fatalf("result %v", err)
				}
			default:
				if code(err) != tc.code {
					t.Fatalf("result %v", err)
				}
			}
		})
	}
}
