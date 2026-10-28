package sshtunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

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
