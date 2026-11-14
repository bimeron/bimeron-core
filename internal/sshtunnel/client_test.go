package sshtunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/testutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestVerifiedSSHForwarding(t *testing.T) {
	_, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(serverKey)
	_, userKey, _ := ed25519.GenerateKey(rand.Reader)
	userSigner, _ := ssh.NewSignerFromKey(userKey)
	server := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if string(key.Marshal()) != string(userSigner.PublicKey().Marshal()) {
			return nil, io.EOF
		}
		return nil, nil
	}}
	server.AddHostKey(hostSigner)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, chans, reqs, err := ssh.NewServerConn(conn, server)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					if ch.ChannelType() != "direct-tcpip" {
						ch.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					c, reqs, err := ch.Accept()
					if err != nil {
						return
					}
					go ssh.DiscardRequests(reqs)
					go func() { defer c.Close(); io.Copy(c, c) }()
				}
			}()
		}
	}()
	dir := t.TempDir()
	identity := filepath.Join(dir, "id_ed25519")
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(userKey)
	if err := os.WriteFile(identity, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
		t.Fatal(err)
	}
	hosts := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(hosts, []byte(knownhosts.Line([]string{l.Addr().String()}, hostSigner.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(l.Addr().String())
	p, err := accesskey.ParseSSH("ssh://alice@" + net.JoinHostPort(host, port))
	if err != nil {
		t.Fatal(err)
	}
	p.SSH.IdentityFile, p.SSH.KnownHostsFile = identity, hosts
	hostAddress := l.Addr().String()
	if os.Getenv("BIMERON_SHADOWTLS_BIN") != "" {
		server := testutil.StartShadowTLS(t, hostAddress)
		server.Wrap(&p, nil)
		testutil.TrustShadowTLS(t, server)
		hostAddress = net.JoinHostPort(p.TCP.Host, strconv.Itoa(p.TCP.Port))
		if err := os.WriteFile(hosts, []byte(knownhosts.Line([]string{hostAddress}, hostSigner.PublicKey())+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	client, err := New(context.Background(), p, net.Dialer{}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	stream, err := client.DialStream(context.Background(), "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(stream, b); err != nil || string(b) != "ping" {
		t.Fatalf("forwarded %q: %v", b, err)
	}
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(otherKey)
	if err := os.WriteFile(hosts, []byte(knownhosts.Line([]string{hostAddress}, otherSigner.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), p, net.Dialer{}, nil, false); err == nil || !strings.Contains(err.Error(), "host-key") {
		t.Fatalf("untrusted host accepted: %v", err)
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("home directory unavailable")
	}
	for in, want := range map[string]string{
		"":               "",
		"~":              home,
		"~/.ssh/id":      filepath.Join(home, ".ssh", "id"),
		`~\.ssh\id`:      filepath.Join(home, `.ssh\id`),
		"~alice/id":      "~alice/id",
		"relative/hosts": "relative/hosts",
	} {
		got, err := expand(in, false)
		if err != nil || got != want {
			t.Errorf("expand(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if got, err := expand("~", true); err == nil {
		t.Errorf("profile-only expand(\"~\") = %q, want an error", got)
	}
}

// startServer runs an SSH server that offers the given host keys and accepts
// only the returned identity file.
func startServer(t *testing.T, hostKeys ...ssh.Signer) (address, identity string) {
	t.Helper()
	_, userKey, _ := ed25519.GenerateKey(rand.Reader)
	userSigner, _ := ssh.NewSignerFromKey(userKey)
	server := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if string(key.Marshal()) != string(userSigner.PublicKey().Marshal()) {
			return nil, io.EOF
		}
		return nil, nil
	}}
	for _, k := range hostKeys {
		server.AddHostKey(k)
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
				_, chans, reqs, err := ssh.NewServerConn(conn, server)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					ch.Reject(ssh.Prohibited, "unused")
				}
			}()
		}
	}()
	identity = filepath.Join(t.TempDir(), "id_ed25519")
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(userKey)
	if err := os.WriteFile(identity, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
		t.Fatal(err)
	}
	return l.Addr().String(), identity
}

func sshProfile(t *testing.T, address, identity string, hostKeys ...ssh.PublicKey) accesskey.Profile {
	t.Helper()
	p, err := accesskey.ParseSSH("ssh://alice@" + address)
	if err != nil {
		t.Fatal(err)
	}
	var lines []byte
	for _, k := range hostKeys {
		lines = append(lines, knownhosts.Line([]string{address}, k)+"\n"...)
	}
	hosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(hosts, lines, 0600); err != nil {
		t.Fatal(err)
	}
	p.SSH.IdentityFile, p.SSH.KnownHostsFile = identity, hosts
	return p
}

func TestNewFailureClassification(t *testing.T) {
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostKey)
	address, identity := startServer(t, hostSigner)

	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(otherKey)
	_, err := New(context.Background(), sshProfile(t, address, identity, otherSigner.PublicKey()), net.Dialer{}, nil, false)
	if err == nil || errors.Is(err, ErrNetwork) {
		t.Fatalf("host-key mismatch: %v", err)
	}

	_, wrongUser, _ := ed25519.GenerateKey(rand.Reader)
	wrongBytes, _ := x509.MarshalPKCS8PrivateKey(wrongUser)
	wrongIdentity := filepath.Join(t.TempDir(), "id_wrong")
	if err := os.WriteFile(wrongIdentity, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: wrongBytes}), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = New(context.Background(), sshProfile(t, address, wrongIdentity, hostSigner.PublicKey()), net.Dialer{}, nil, false)
	if err == nil || errors.Is(err, ErrNetwork) {
		t.Fatalf("authentication rejection: %v", err)
	}

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := closed.Addr().String()
	closed.Close()
	_, err = New(context.Background(), sshProfile(t, refused, identity, hostSigner.PublicKey()), net.Dialer{}, nil, false)
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("refused connection: %v", err)
	}

	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { conn.Close() })
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = New(ctx, sshProfile(t, silent.Addr().String(), identity, hostSigner.PublicKey()), net.Dialer{}, nil, false)
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("stalled handshake: %v", err)
	}
}
