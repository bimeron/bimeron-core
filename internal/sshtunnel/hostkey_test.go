package sshtunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func hostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// hostKeyServer accepts unauthenticated sessions with the given host keys.
func hostKeyServer(t *testing.T, keys ...ssh.Signer) string {
	t.Helper()
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	for _, k := range keys {
		cfg.AddHostKey(k)
	}
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
				c, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer c.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					ch.Reject(ssh.Prohibited, "fixture")
				}
			}()
		}
	}()
	return l.Addr().String()
}

type offers struct {
	mu     sync.Mutex
	seen   []Challenge
	answer func(context.Context, Challenge) ([]string, error)
}

func (o *offers) prompt(ctx context.Context, c Challenge) ([]string, error) {
	o.mu.Lock()
	o.seen = append(o.seen, c)
	o.mu.Unlock()
	if o.answer == nil {
		return []string{HostKeyAccept}, nil
	}
	return o.answer(ctx, c)
}

func (o *offers) count() int { o.mu.Lock(); defer o.mu.Unlock(); return len(o.seen) }

func connect(t *testing.T, address, knownHostsFile string, keys *HostKeys, o *offers) error {
	t.Helper()
	p, err := accesskey.ParseSSH("ssh://alice@" + address)
	if err != nil {
		t.Fatal(err)
	}
	p.SSH.KnownHostsFile = knownHostsFile
	var prompt Prompt
	if o != nil {
		prompt = o.prompt
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := NewWithHostKeys(ctx, p, net.Dialer{}, prompt, false, keys)
	if c != nil {
		c.Close()
	}
	return err
}

func code(err error) string {
	var e *HostKeyError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func writeHosts(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustKeys(t *testing.T, data string) *HostKeys {
	t.Helper()
	k, err := ParseHostKeys([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestHostKeyAcceptNew(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	server := hostSigner(t)
	address := hostKeyServer(t, server)
	keys := mustKeys(t, "")
	o := &offers{}
	if err := connect(t, address, "", keys, o); err != nil {
		t.Fatal(err)
	}
	if o.count() != 1 {
		t.Fatalf("offers %d", o.count())
	}
	c := o.seen[0]
	host, port, _ := net.SplitHostPort(address)
	want := HostKeyOffer{Host: net.JoinHostPort(host, port), KeyType: "ssh-ed25519", Fingerprint: ssh.FingerprintSHA256(server.PublicKey()), KnownHostsLine: knownhosts.Line([]string{address}, server.PublicKey())}
	if c.Kind != HostKeyKind || c.HostKey == nil || *c.HostKey != want || len(c.Prompts) != 0 || len(c.Echo) != 0 {
		t.Fatalf("offer %+v", c)
	}
	if !strings.HasPrefix(want.Fingerprint, "SHA256:") || strings.HasSuffix(want.Fingerprint, "=") || !strings.HasPrefix(want.KnownHostsLine, "[127.0.0.1]:"+port+" ssh-ed25519 ") {
		t.Fatalf("format %+v", want)
	}
	// The same session remembers the accepted key across reconnects.
	if err := connect(t, address, "", keys, o); err != nil || o.count() != 1 {
		t.Fatalf("reconnect %v offers %d", err, o.count())
	}
	// A new session supplied with the persisted line does not offer.
	fresh := &offers{}
	if err := connect(t, address, "", mustKeys(t, "# app-owned\n"+want.KnownHostsLine+"\n"), fresh); err != nil || fresh.count() != 0 {
		t.Fatalf("persisted %v offers %d", err, fresh.count())
	}
}

func TestHostKeyDeclinedAndUnanswered(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	address := hostKeyServer(t, hostSigner(t))
	for name, tc := range map[string]struct {
		answer func(context.Context, Challenge) ([]string, error)
		code   string
	}{
		"declined":     {func(context.Context, Challenge) ([]string, error) { return nil, ErrHostKeyDeclined }, HostKeyRejected},
		"wrong_answer": {func(context.Context, Challenge) ([]string, error) { return []string{"yes"}, nil }, HostKeyRejected},
		"withdrawn":    {func(context.Context, Challenge) ([]string, error) { return nil, errors.New("gone") }, HostKeyUnanswered},
	} {
		t.Run(name, func(t *testing.T) {
			keys := mustKeys(t, "")
			o := &offers{answer: tc.answer}
			err := connect(t, address, "", keys, o)
			if code(err) != tc.code || o.count() != 1 {
				t.Fatalf("result %v offers %d", err, o.count())
			}
			// Nothing was remembered.
			o.answer = nil
			if err := connect(t, address, "", keys, o); err != nil || o.count() != 2 {
				t.Fatalf("retry %v offers %d", err, o.count())
			}
		})
	}
}

func TestHostKeyOfferTimeout(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	old := promptTimeout
	promptTimeout = 300 * time.Millisecond
	t.Cleanup(func() { promptTimeout = old })
	address := hostKeyServer(t, hostSigner(t))
	o := &offers{answer: func(ctx context.Context, _ Challenge) ([]string, error) { <-ctx.Done(); return nil, ctx.Err() }}
	started := time.Now()
	err := connect(t, address, "", mustKeys(t, ""), o)
	if code(err) != HostKeyUnanswered || o.count() != 1 || time.Since(started) > 5*time.Second {
		t.Fatalf("result %v offers %d after %v", err, o.count(), time.Since(started))
	}
}

func TestHostKeyKnown(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	server, other := hostSigner(t), hostSigner(t)
	address := hostKeyServer(t, server)
	good := knownhosts.Line([]string{address}, server.PublicKey())
	bad := knownhosts.Line([]string{address}, other.PublicKey())
	hashed := knownhosts.HashHostname(knownhosts.Normalize(address)) + " " + strings.SplitN(good, " ", 2)[1]
	revoked := "@revoked * " + strings.SplitN(good, " ", 2)[1]
	for name, tc := range map[string]struct {
		file, trusted, code string
	}{
		"trusted_match":           {"", good, ""},
		"file_match":              {writeHosts(t, good), "", ""},
		"file_hashed_import":      {writeHosts(t, hashed), "", ""},
		"either_source_matches":   {writeHosts(t, bad), good, ""},
		"trusted_changed":         {"", bad, HostKeyMismatch},
		"file_changed":            {writeHosts(t, bad), "", HostKeyMismatch},
		"file_revoked":            {writeHosts(t, revoked), good, HostKeyMismatch},
		"file_other_host_unknown": {writeHosts(t, knownhosts.Line([]string{"example.com:22"}, other.PublicKey())), "", "offer"},
	} {
		t.Run(name, func(t *testing.T) {
			o := &offers{answer: func(context.Context, Challenge) ([]string, error) { return nil, ErrHostKeyDeclined }}
			err := connect(t, address, tc.file, mustKeys(t, tc.trusted), o)
			switch tc.code {
			case "":
				if err != nil || o.count() != 0 {
					t.Fatalf("result %v offers %d", err, o.count())
				}
			case "offer":
				if code(err) != HostKeyRejected || o.count() != 1 {
					t.Fatalf("result %v offers %d", err, o.count())
				}
			default:
				if code(err) != tc.code || o.count() != 0 {
					t.Fatalf("result %v offers %d", err, o.count())
				}
			}
		})
	}
}

func TestHostKeyPrefersKnownType(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	ed := hostSigner(t)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecSigner, _ := ssh.NewSignerFromKey(ec)
	// The library default prefers ECDSA; trusting only Ed25519 must not be a mismatch.
	address := hostKeyServer(t, ecSigner, ed)
	if err := connect(t, address, "", mustKeys(t, knownhosts.Line([]string{address}, ed.PublicKey())), &offers{}); err != nil {
		t.Fatal(err)
	}
	if err := connect(t, address, writeHosts(t, knownhosts.Line([]string{address}, ed.PublicKey())), mustKeys(t, ""), &offers{}); err != nil {
		t.Fatal(err)
	}
	v := &verifier{keys: mustKeys(t, ""), ca: true}
	if v.algorithms(address, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}) != nil {
		t.Fatal("CA file must keep library order")
	}
}

func TestHostKeyNoOptIn(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	address := hostKeyServer(t, hostSigner(t))
	o := &offers{}
	err := connect(t, address, writeHosts(t, "# empty"), nil, o)
	if err == nil || code(err) != "" || err.Error() != "SSH handshake or host-key verification failed" || o.count() != 0 {
		t.Fatalf("legacy result %v offers %d", err, o.count())
	}
	if err := connect(t, address, "", nil, o); err == nil || err.Error() != "SSH known_hosts file must be selected for service use" {
		t.Fatalf("legacy missing file %v", err)
	}
	// Without a prompt an unknown host cannot be offered.
	_, user, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(user, "")
	identity := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(identity, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	p, _ := accesskey.ParseSSH("ssh://alice@" + address)
	p.SSH.IdentityFile = identity
	if _, err := NewWithHostKeys(context.Background(), p, net.Dialer{}, nil, false, mustKeys(t, "")); code(err) != HostKeyUnknown {
		t.Fatalf("no prompt %v", err)
	}
}

func TestParseHostKeys(t *testing.T) {
	key := strings.SplitN(knownhosts.Line([]string{"a:22"}, hostSigner(t).PublicKey()), " ", 2)[1]
	good := []string{"", "# c\n\n", "example.com " + key, "example.com,[10.0.0.1]:2222 " + key + " comment here", "[::1]:22 " + key, "\r\n[host]:22 " + key + "\r\n"}
	for _, g := range good {
		if _, err := ParseHostKeys([]byte(g)); err != nil {
			t.Fatalf("%q: %v", g, err)
		}
	}
	bad := []string{"*.example.com " + key, "!example.com " + key, "@revoked example.com " + key, "@cert-authority example.com " + key,
		knownhosts.HashHostname("example.com") + " " + key, "example.com ssh-ed25519 AAAA", "example.com", "ex ample.com " + key,
		"[example.com]:0 " + key, "[example.com]:022 " + key, "[example.com] " + key, "exa]mple.com " + key, strings.Repeat("#", maxTrustedHostKeys+1)}
	for _, b := range bad {
		if _, err := ParseHostKeys([]byte(b)); err == nil {
			t.Fatalf("accepted %q", b)
		}
	}
	k := mustKeys(t, "[example.com]:22 "+key)
	if len(k.lookup("example.com")) != 1 {
		t.Fatal("port 22 not normalized")
	}
}
