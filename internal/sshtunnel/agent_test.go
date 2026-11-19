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

// withListTimeout shortens the agent listing timeout for the test.
func withListTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	previous := agentListTimeout
	agentListTimeout = d
	t.Cleanup(func() { agentListTimeout = previous })
}

// startKeyServer accepts public-key authentication with key only, answering
// each key check after delay.
func startKeyServer(t *testing.T, key ssh.PublicKey, delay time.Duration) (address string, host ssh.PublicKey) {
	t.Helper()
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostKey)
	server := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, offered ssh.PublicKey) (*ssh.Permissions, error) {
		time.Sleep(delay)
		if string(offered.Marshal()) != string(key.Marshal()) {
			return nil, errors.New("rejected")
		}
		return nil, nil
	}}
	server.AddHostKey(hostSigner)
	return serveSSH(t, server), hostSigner.PublicKey()
}

// keyringAgent serves a keyring with one new key over a pipe, through a.
func keyringAgent(t *testing.T, wrap func(agent.ExtendedAgent) agent.Agent) (ssh.PublicKey, func(context.Context) (net.Conn, error)) {
	t.Helper()
	_, userKey, _ := ed25519.GenerateKey(rand.Reader)
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: userKey}); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(userKey)
	if err != nil {
		t.Fatal(err)
	}
	served := wrap(keyring.(agent.ExtendedAgent))
	return signer.PublicKey(), func(context.Context) (net.Conn, error) {
		local, remote := net.Pipe()
		go agent.ServeAgent(served, remote)
		return local, nil
	}
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
	withListTimeout(t, 200*time.Millisecond)
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

// The listing deadline does not apply to signing: an agent login still works
// when the handshake reaches the signature after the listing timeout.
func TestAgentSignsAfterListingTimeout(t *testing.T) {
	withListTimeout(t, 500*time.Millisecond)
	key, dial := keyringAgent(t, func(a agent.ExtendedAgent) agent.Agent { return a })
	withAgent(t, dial)
	address, host := startKeyServer(t, key, time.Second)
	p := sshProfile(t, address, "", host)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := NewWithOptions(ctx, p, net.Dialer{}, nil, Options{})
	if err != nil {
		t.Fatal("agent login failed after the listing timeout:", err)
	}
	client.Close()
}

// stalledSigner lists its keys but never signs; entered is closed at the
// first signature request.
type stalledSigner struct {
	agent.ExtendedAgent
	entered chan struct{}
	once    *sync.Once
	release chan struct{}
}

func (s stalledSigner) Sign(ssh.PublicKey, []byte) (*ssh.Signature, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return nil, errors.New("released")
}
func (s stalledSigner) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	return s.Sign(key, data)
}

// A signature request that the agent never answers ends with the attempt:
// the agent connection is closed when the context ends.
func TestStalledAgentSignatureEndsWithContext(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	entered := make(chan struct{})
	key, dial := keyringAgent(t, func(a agent.ExtendedAgent) agent.Agent {
		return stalledSigner{ExtendedAgent: a, entered: entered, once: new(sync.Once), release: release}
	})
	withAgent(t, dial)
	address, host := startKeyServer(t, key, 0)
	p := sshProfile(t, address, "", host)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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
	case <-time.After(15 * time.Second):
		t.Fatal("a stalled agent signature outlived the context")
	}
	select {
	case <-entered:
	default:
		t.Fatal("the handshake never asked the agent for a signature")
	}
}
