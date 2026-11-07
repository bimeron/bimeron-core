package sshtunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
	c, err := NewWithOptions(ctx, p, net.Dialer{}, prompt, Options{HostKeys: keys})
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
	if _, err := NewWithOptions(context.Background(), p, net.Dialer{}, nil, Options{HostKeys: mustKeys(t, "")}); code(err) != HostKeyUnknown {
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

func connectAs(t *testing.T, host, address, knownHostsFile string, keys *HostKeys, o *offers) error {
	t.Helper()
	_, port, _ := net.SplitHostPort(address)
	return connect(t, net.JoinHostPort(host, port), knownHostsFile, keys, o)
}

func declineAll() *offers {
	return &offers{answer: func(context.Context, Challenge) ([]string, error) { return nil, ErrHostKeyDeclined }}
}

// Host names match case-insensitively, as in OpenSSH: a changed key behind a
// differently cased name is a mismatch, never a new host.
func TestHostKeyHostCase(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	trusted, presented := hostSigner(t), hostSigner(t)
	address := hostKeyServer(t, presented)
	_, port, _ := net.SplitHostPort(address)
	lower := knownhosts.Line([]string{"localhost:" + port}, trusted.PublicKey())
	upper := knownhosts.Line([]string{"LocalHost:" + port}, trusted.PublicKey())
	for name, tc := range map[string]struct {
		dial, file, trusted, code string
	}{
		"trusted_lower_dial_upper": {"LOCALHOST", "", lower, HostKeyMismatch},
		"trusted_upper_dial_lower": {"localhost", "", upper, HostKeyMismatch},
		"file_lower_dial_upper":    {"LOCALHOST", writeHosts(t, lower), "", HostKeyMismatch},
		"file_hashed_dial_upper":   {"LOCALHOST", writeHosts(t, knownhosts.HashHostname("[localhost]:"+port)+" "+strings.SplitN(lower, " ", 2)[1]), "", HostKeyMismatch},
		"file_upper_dial_same":     {"LocalHost", writeHosts(t, upper), "", HostKeyMismatch},
		// knownhosts cannot match a mixed-case pattern against another case,
		// so such a file never yields offers.
		"file_upper_dial_lower": {"localhost", writeHosts(t, upper), "", HostKeyUnknown},
	} {
		t.Run(name, func(t *testing.T) {
			o := declineAll()
			if err := connectAs(t, tc.dial, address, tc.file, mustKeys(t, tc.trusted), o); code(err) != tc.code || o.count() != 0 {
				t.Fatalf("result %v offers %d", err, o.count())
			}
		})
	}
	// A matching key under either case connects.
	good := knownhosts.Line([]string{"localhost:" + port}, presented.PublicKey())
	if err := connectAs(t, "LOCALHOST", address, writeHosts(t, good), mustKeys(t, ""), declineAll()); err != nil {
		t.Fatal(err)
	}
	if err := connectAs(t, "LocalHost", address, writeHosts(t, knownhosts.Line([]string{"LocalHost:" + port}, presented.PublicKey())), mustKeys(t, ""), declineAll()); err != nil {
		t.Fatal(err)
	}
	// Offers and stored lines use the lowercase host; the session then knows
	// the host under any case.
	keys, o := mustKeys(t, ""), &offers{}
	if err := connectAs(t, "LOCALHOST", address, "", keys, o); err != nil || o.count() != 1 {
		t.Fatalf("offer %v %d", err, o.count())
	}
	if offer := o.seen[0].HostKey; offer.Host != "localhost:"+port || offer.KnownHostsLine != good {
		t.Fatalf("offer %+v", offer)
	}
	if err := connectAs(t, "localhost", address, "", keys, o); err != nil || o.count() != 1 {
		t.Fatalf("reconnect %v %d", err, o.count())
	}
}

func hostCert(t *testing.T, ca, host ssh.Signer, principal string) ssh.Signer {
	t.Helper()
	cert := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: []string{principal}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(cert, host)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A known_hosts file with @cert-authority lines never produces offers.
// knownhosts CA patterns need an exact port, so "*" does not cover a non-22
// port and cannot prove such a host unknown.
func TestHostKeyCertificateAuthority(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	ca, otherCA, hostKey, plain := hostSigner(t), hostSigner(t), hostSigner(t), hostSigner(t)
	certServer := hostKeyServer(t, hostCert(t, ca, hostKey, "127.0.0.1"))
	foreignServer := hostKeyServer(t, hostCert(t, otherCA, hostKey, "127.0.0.1"))
	plainServer := hostKeyServer(t, plain)
	caKey := strings.SplitN(knownhosts.Line([]string{"a:22"}, ca.PublicKey()), " ", 2)[1]
	exact := func(address string) string { return "@cert-authority " + knownhosts.Normalize(address) + " " + caKey }
	for name, tc := range map[string]struct {
		server, file, trusted, code string
	}{
		"exact_cert":             {certServer, exact(certServer), "", ""},
		"exact_plain":            {plainServer, exact(plainServer), "", HostKeyMismatch},
		"wildcard_plain":         {plainServer, "@cert-authority * " + caKey, "", HostKeyCARequired},
		"wildcard_port_plain":    {plainServer, "@cert-authority [127.0.0.*]:* " + caKey, "", HostKeyCARequired},
		"other_host_plain":       {plainServer, "@cert-authority *.example.com " + caKey, "", HostKeyCARequired},
		"exact_other_port_plain": {plainServer, exact(certServer), "", HostKeyCARequired},
		"trusted_plain_match":    {plainServer, "@cert-authority * " + caKey, knownhosts.Line([]string{plainServer}, plain.PublicKey()), ""},
		// Certificates the file cannot verify fail without a host-key code:
		// a foreign CA, or a wildcard CA line on a non-22 port.
		"exact_foreign_cert": {foreignServer, exact(foreignServer), "", "generic"},
		"wildcard_cert":      {certServer, "@cert-authority * " + caKey, "", "generic"},
	} {
		t.Run(name, func(t *testing.T) {
			o := &offers{}
			err := connect(t, tc.server, writeHosts(t, tc.file), mustKeys(t, tc.trusted), o)
			switch {
			case o.count() != 0:
				t.Fatalf("offered %+v", o.seen[0].HostKey)
			case tc.code == "":
				if err != nil {
					t.Fatal(err)
				}
			case tc.code == "generic":
				if err == nil || code(err) != "" {
					t.Fatalf("result %v", err)
				}
			case code(err) != tc.code:
				t.Fatalf("result %v want %s", err, tc.code)
			}
		})
	}
}

// Several keys for one host: any listed key connects, any other is refused.
func TestHostKeyMultipleKeysPerHost(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	k1, k2, k3 := hostSigner(t), hostSigner(t), hostSigner(t)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecSigner, _ := ssh.NewSignerFromKey(ec)
	two := hostKeyServer(t, k2)
	three := hostKeyServer(t, k3)
	both := hostKeyServer(t, ecSigner, k1)
	line := func(address string, s ssh.Signer) string { return knownhosts.Line([]string{address}, s.PublicKey()) }
	retarget := func(l, from, to string) string {
		return knownhosts.Normalize(to) + strings.TrimPrefix(l, knownhosts.Normalize(from))
	}
	for name, tc := range map[string]struct {
		server, file, trusted, code string
	}{
		"trusted_second":     {two, "", line(two, k1) + "\n" + line(two, k2), ""},
		"trusted_neither":    {three, "", line(three, k1) + "\n" + line(three, k2), HostKeyMismatch},
		"trusted_multi_host": {two, "", "example.com," + line(two, k2), ""},
		"file_second":        {two, writeHosts(t, line(two, k1), line(two, k2)), "", ""},
		"file_neither":       {three, writeHosts(t, line(three, k1), line(three, k2)), "", HostKeyMismatch},
		"split_sources":      {two, writeHosts(t, line(two, k1)), line(two, k2), ""},
		"split_neither":      {three, writeHosts(t, line(three, k1)), line(three, k2), HostKeyMismatch},
		"server_two_types":   {both, "", line(both, k1) + "\n" + line(both, ecSigner), ""},
		"server_ecdsa_known": {both, "", retarget(line(two, ecSigner), two, both), ""},
	} {
		t.Run(name, func(t *testing.T) {
			o := declineAll()
			if err := connect(t, tc.server, tc.file, mustKeys(t, tc.trusted), o); code(err) != tc.code || (tc.code == "") != (err == nil) || o.count() != 0 {
				t.Fatalf("result %v offers %d", err, o.count())
			}
		})
	}
}

// First contact prefers Ed25519, then ECDSA, then RSA, then certificates.
func TestHostKeyFirstContactOrder(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	v := &verifier{keys: mustKeys(t, "")}
	got := v.algorithms("127.0.0.1:2222", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222})
	rank := map[string]int{}
	for i, name := range got {
		rank[name] = i
	}
	if got[0] != ssh.KeyAlgoED25519 || rank[ssh.KeyAlgoECDSA256] > rank[ssh.KeyAlgoRSASHA256] || rank[ssh.KeyAlgoRSA] > rank[ssh.CertAlgoED25519v01] || len(rank) != len(got) {
		t.Fatalf("order %v", got)
	}
	for _, name := range ssh.SupportedAlgorithms().HostKeys {
		if _, ok := rank[name]; !ok {
			t.Fatalf("missing %s in %v", name, got)
		}
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, _ := ssh.NewSignerFromKey(rsaKey)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecSigner, _ := ssh.NewSignerFromKey(ec)
	for _, servers := range [][]ssh.Signer{{rsaSigner, ecSigner, hostSigner(t)}, {rsaSigner, ecSigner}} {
		o := declineAll()
		connect(t, hostKeyServer(t, servers...), "", mustKeys(t, ""), o)
		want := servers[len(servers)-1].PublicKey().Type()
		if o.count() != 1 || o.seen[0].HostKey.KeyType != want {
			t.Fatalf("offers %d %+v want %s", o.count(), o.seen, want)
		}
	}
}

// Answers a prompt returned without error are used even if its context ended
// meanwhile, so an accepted reply is never reported as unanswered.
func TestAttemptAnswerAfterDeadline(t *testing.T) {
	old := promptTimeout
	promptTimeout = 20 * time.Millisecond
	t.Cleanup(func() { promptTimeout = old })
	a := newAttempt(context.Background())
	defer a.close()
	p := a.prompt(func(ctx context.Context, _ Challenge) ([]string, error) {
		<-ctx.Done()
		return []string{HostKeyAccept}, nil
	})
	if answers, err := p(a.ctx, Challenge{}); err != nil || len(answers) != 1 || a.ctx.Err() != nil {
		t.Fatalf("answers %v err %v", answers, err)
	}
}
