package sshtunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// withAgent replaces the platform agent for the duration of the test.
func withAgent(t *testing.T, dial func(context.Context) (net.Conn, error)) {
	t.Helper()
	previous := dialAgent
	dialAgent = dial
	t.Cleanup(func() { dialAgent = previous })
}

// startKeyServer accepts public-key authentication with key only.
func startKeyServer(t *testing.T, key ssh.PublicKey) (address string, host ssh.PublicKey) {
	t.Helper()
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostKey)
	server := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, offered ssh.PublicKey) (*ssh.Permissions, error) {
		if string(offered.Marshal()) != string(key.Marshal()) {
			return nil, errors.New("rejected")
		}
		return nil, nil
	}}
	server.AddHostKey(hostSigner)
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
	return l.Addr().String(), hostSigner.PublicKey()
}

// NoAgent and ProfileOnly never dial the agent; otherwise it is dialed once.
func TestNoAgentNeverDialsAgent(t *testing.T) {
	var dials atomic.Int32
	withAgent(t, func(context.Context) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("no agent")
	})
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostKey)
	address, identity := startServer(t, hostSigner)
	p := sshProfile(t, address, identity, hostSigner.PublicKey())
	for _, test := range []struct {
		name  string
		o     Options
		dials int32
	}{
		{"daemon", Options{NoAgent: true}, 0},
		{"profile only", Options{ProfileOnly: true}, 0},
		{"foreground", Options{}, 1},
	} {
		dials.Store(0)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		client, err := NewWithOptions(ctx, p, net.Dialer{}, nil, test.o)
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		client.Close()
		if got := dials.Load(); got != test.dials {
			t.Errorf("%s: %d agent dials, want %d", test.name, got, test.dials)
		}
	}
}

// An agent that accepts the connection and never answers delays the
// connection only by the listing timeout, and its connection is closed.
func TestSilentAgentIsBounded(t *testing.T) {
	previous := agentListTimeout
	agentListTimeout = 200 * time.Millisecond
	t.Cleanup(func() { agentListTimeout = previous })
	closed := make(chan struct{})
	withAgent(t, func(context.Context) (net.Conn, error) {
		local, remote := net.Pipe()
		go func() {
			defer close(closed)
			io.Copy(io.Discard, remote)
		}()
		return local, nil
	})
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostKey)
	address, identity := startServer(t, hostSigner)
	p := sshProfile(t, address, identity, hostSigner.PublicKey())
	done := make(chan error, 1)
	go func() {
		client, err := NewWithOptions(context.Background(), p, net.Dialer{}, nil, Options{})
		if err == nil {
			client.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("identity file login failed behind a silent agent:", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a silent agent blocked the connection")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("silent agent connection left open")
	}
}

// stalledSigner lists its keys but never signs.
type stalledSigner struct {
	agent.ExtendedAgent
	release chan struct{}
}

func (s stalledSigner) Sign(ssh.PublicKey, []byte) (*ssh.Signature, error) {
	<-s.release
	return nil, errors.New("released")
}
func (s stalledSigner) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	return s.Sign(key, data)
}

// A signature request that the agent never answers ends with the attempt:
// the agent connection is closed when the context ends.
func TestStalledAgentSignatureEndsWithContext(t *testing.T) {
	_, userKey, _ := ed25519.GenerateKey(rand.Reader)
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: userKey}); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stalled := stalledSigner{ExtendedAgent: keyring.(agent.ExtendedAgent), release: release}
	var local *closeConn
	withAgent(t, func(context.Context) (net.Conn, error) {
		end, remote := net.Pipe()
		local = &closeConn{Conn: end, closed: make(chan struct{})}
		go agent.ServeAgent(stalled, remote)
		return local, nil
	})
	signer, _ := ssh.NewSignerFromKey(userKey)
	address, host := startKeyServer(t, signer.PublicKey())
	p := sshProfile(t, address, "", host)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		client, err := NewWithOptions(ctx, p, net.Dialer{}, nil, Options{})
		if err == nil {
			client.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("login succeeded without a signature")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled agent signature outlived the context")
	}
	select {
	case <-local.closed:
	default:
		t.Fatal("stalled agent connection left open")
	}
}

// closeConn reports when it is closed.
type closeConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *closeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
