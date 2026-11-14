// Package sshtunnel provides verified SSH direct TCP forwarding.
package sshtunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/streamtransport"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Challenge is shown only to a local authenticated client, never in status or logs.
type Challenge struct {
	Kind    string   `json:"kind"`
	Prompts []string `json:"prompts"`
	Echo    []bool   `json:"echo"`
	// HostKey is set only for Kind HostKeyKind, which has no prompts. It is
	// never serialized by the control protocol.
	HostKey *HostKeyOffer `json:"-"`
}
type Prompt func(context.Context, Challenge) ([]string, error)

type Client struct {
	ssh   *ssh.Client
	agent net.Conn
	once  sync.Once
}
type streamConn struct {
	net.Conn
	closeWrite func() error
}

func (c streamConn) CloseRead() error  { return c.Conn.Close() }
func (c streamConn) CloseWrite() error { return c.closeWrite() }

var _ transport.StreamDialer = (*Client)(nil)

// ErrNetwork marks connection failures caused by the network path to the
// server: timeouts, refused or reset connections, unreachable routes, and DNS
// errors. Authentication, host-key, and configuration failures never match it,
// so callers may retry exactly the errors for which errors.Is reports true.
var ErrNetwork = errors.New("SSH server unavailable")

// fileTrace observes filesystem access for tests; see SetFileTrace.
var fileTrace atomic.Pointer[func(op, path string)]

// SetFileTrace installs f to observe every filesystem access this package
// makes for a connection: op is "home" (user home lookup, path empty), "stat",
// "read" or "agent" (agent socket dial). It exists for tests that prove which
// paths a session touches. It returns a function restoring the previous trace.
func SetFileTrace(f func(op, path string)) (restore func()) {
	old := fileTrace.Swap(&f)
	return func() { fileTrace.Store(old) }
}

func trace(op, path string) {
	if f := fileTrace.Load(); f != nil && *f != nil {
		(*f)(op, path)
	}
}

func userHomeDir() (string, error) {
	trace("home", "")
	return os.UserHomeDir()
}

func readFile(path string) ([]byte, error) {
	trace("read", path)
	return os.ReadFile(path)
}

func homeRelative(path string) bool {
	return path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`)
}

func expand(path string, profileOnly bool) (string, error) {
	if path == "" {
		return "", nil
	}
	if homeRelative(path) {
		if profileOnly {
			return "", fmt.Errorf("SSH home-relative path unavailable")
		}
		home, err := userHomeDir()
		if err != nil {
			return "", fmt.Errorf("SSH home directory unavailable")
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func signer(path string, ctx context.Context, prompt Prompt) (ssh.Signer, error) {
	b, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("SSH identity file unavailable")
	}
	s, err := ssh.ParsePrivateKey(b)
	if err == nil {
		return s, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, fmt.Errorf("invalid SSH identity file")
	}
	if prompt == nil {
		return nil, fmt.Errorf("SSH key passphrase required")
	}
	answers, err := prompt(ctx, Challenge{Kind: "key_passphrase", Prompts: []string{"Key passphrase"}, Echo: []bool{false}})
	if err != nil || len(answers) != 1 {
		return nil, fmt.Errorf("SSH key passphrase unavailable")
	}
	s, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(answers[0]))
	if err != nil {
		return nil, fmt.Errorf("SSH key passphrase rejected")
	}
	return s, nil
}

func New(ctx context.Context, p accesskey.Profile, dialer net.Dialer, prompt Prompt, defaultKeys bool) (*Client, error) {
	return NewWithOptions(ctx, p, dialer, prompt, Options{DefaultKeys: defaultKeys})
}

// Options configures NewWithOptions. The zero value is New with defaultKeys
// false.
type Options struct {
	// DefaultKeys permits the user-home fallbacks: ~/.ssh/known_hosts without
	// a KnownHostsFile, and ~/.ssh/id_{ed25519,ecdsa,rsa} without an
	// IdentityFile. Ignored with ProfileOnly.
	DefaultKeys bool
	// HostKeys enables accept-new: an unknown host is offered through prompt
	// as a HostKeyKind challenge, a known host with another key is refused
	// without an offer, and failures are reported as *HostKeyError. Nil keeps
	// file-only verification.
	HostKeys *HostKeys
	// ProfileOnly restricts the connection to the files the profile names:
	// no user home lookup, no "~" path, no default identity or known_hosts,
	// and no SSH agent. Without a KnownHostsFile and without HostKeys the
	// connection fails with HostKeyError KnownHostsMissing. The Android
	// embedding always sets it.
	ProfileOnly bool
}

// NewWithOptions connects like New with explicit options.
func NewWithOptions(ctx context.Context, p accesskey.Profile, dialer net.Dialer, prompt Prompt, o Options) (*Client, error) {
	if err := p.ValidateShadowTLS(); err != nil {
		return nil, err
	}
	if p.Type != "ssh" || p.SSH.User == "" || p.TCP.Host == "" || p.TCP.Port < 1 || p.TCP.Port > 65535 {
		return nil, fmt.Errorf("invalid SSH profile")
	}
	defaultKeys := o.DefaultKeys && !o.ProfileOnly
	hostFile, err := expand(p.SSH.KnownHostsFile, o.ProfileOnly)
	if err != nil {
		return nil, err
	}
	var policy *verifier
	if o.HostKeys != nil {
		policy = &verifier{keys: o.HostKeys}
		if hostFile != "" {
			data, err := readFile(hostFile)
			if err != nil {
				return nil, fmt.Errorf("SSH known_hosts unavailable")
			}
			if policy.file, err = knownhosts.New(hostFile); err != nil {
				return nil, fmt.Errorf("SSH known_hosts unavailable")
			}
			policy.ca, policy.folds = inspectHosts(data)
		}
	} else if hostFile == "" {
		if o.ProfileOnly {
			return nil, &HostKeyError{Code: KnownHostsMissing}
		}
		if !defaultKeys {
			return nil, fmt.Errorf("SSH known_hosts file must be selected for service use")
		}
		home, err := userHomeDir()
		if err != nil {
			return nil, fmt.Errorf("SSH known_hosts unavailable")
		}
		hostFile = filepath.Join(home, ".ssh", "known_hosts")
	}
	var verify ssh.HostKeyCallback
	// order chooses the host-key algorithms. In file-only mode it is a
	// verifier without app-owned keys and without prompts, used only for
	// algorithms: verification stays with verify.
	order := policy
	if policy == nil {
		data, err := readFile(hostFile)
		if err != nil {
			return nil, fmt.Errorf("SSH known_hosts unavailable")
		}
		if verify, err = knownhosts.New(hostFile); err != nil {
			return nil, fmt.Errorf("SSH known_hosts unavailable")
		}
		order = &verifier{keys: &HostKeys{}, file: verify}
		order.ca, _ = inspectHosts(data)
	}
	identity, err := expand(p.SSH.IdentityFile, o.ProfileOnly)
	if err != nil {
		return nil, err
	}
	a := newAttempt(ctx)
	defer a.close()
	ctx = a.ctx
	if prompt != nil {
		prompt = a.prompt(prompt)
	}
	var methods []ssh.AuthMethod
	if identity != "" {
		s, err := signer(identity, ctx, prompt)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(s))
	}
	agentConn, err := net.Conn(nil), fmt.Errorf("SSH agent disabled")
	if !o.ProfileOnly {
		agentConn, err = dialAgent(ctx)
	}
	if err == nil {
		if signers, e := agent.NewClient(agentConn).Signers(); e == nil && len(signers) > 0 {
			methods = append(methods, ssh.PublicKeys(signers...))
		} else {
			agentConn.Close()
			agentConn = nil
		}
	}
	if identity == "" && defaultKeys {
		if home, e := userHomeDir(); e == nil {
			for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
				path := filepath.Join(home, ".ssh", name)
				trace("stat", path)
				if _, e := os.Stat(path); e != nil {
					continue
				}
				if s, e := signer(path, ctx, prompt); e == nil {
					methods = append(methods, ssh.PublicKeys(s))
				}
			}
		}
	}
	if prompt != nil {
		methods = append(methods, ssh.PasswordCallback(func() (string, error) {
			a, err := prompt(ctx, Challenge{Kind: "password", Prompts: []string{"SSH account password"}, Echo: []bool{false}})
			if err != nil || len(a) != 1 {
				return "", fmt.Errorf("SSH password unavailable")
			}
			return a[0], nil
		}))
		methods = append(methods, ssh.KeyboardInteractive(func(_ string, _ string, questions []string, echoes []bool) ([]string, error) {
			if len(questions) == 0 || len(questions) > 8 {
				return nil, fmt.Errorf("unsupported SSH authentication challenge")
			}
			return prompt(ctx, Challenge{Kind: "keyboard_interactive", Prompts: questions, Echo: echoes})
		}))
	}
	if len(methods) == 0 {
		if agentConn != nil {
			agentConn.Close()
		}
		return nil, fmt.Errorf("SSH authentication method unavailable")
	}
	address := net.JoinHostPort(p.TCP.Host, strconv.Itoa(p.TCP.Port))
	a.resume()
	dialCtx := ctx
	conn, err := streamtransport.Dial(dialCtx, dialer, address, p.ShadowTLS, nil)
	if err != nil {
		if agentConn != nil {
			agentConn.Close()
		}
		if a.network(err) {
			return nil, ErrNetwork
		}
		return nil, fmt.Errorf("SSH server transport failed")
	}
	stop := context.AfterFunc(dialCtx, func() { _ = conn.Close() })
	callback := verify
	if policy != nil {
		policy.ctx, policy.prompt = ctx, prompt
		callback = policy.check
	}
	var hostKeyFailed atomic.Bool
	config := &ssh.ClientConfig{User: p.SSH.User, Auth: methods, Timeout: 20 * time.Second,
		HostKeyCallback: func(host string, remote net.Addr, key ssh.PublicKey) error {
			err := callback(host, remote, key)
			if err != nil {
				hostKeyFailed.Store(true)
			}
			return err
		},
		HostKeyAlgorithms: order.algorithms(address, conn.RemoteAddr()),
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(attemptConn{Conn: conn, cancel: a.cancel}, address, config)
	stop()
	if err != nil {
		conn.Close()
		if agentConn != nil {
			agentConn.Close()
		}
		if policy != nil {
			if e := policy.result(); e != nil {
				return nil, e
			}
		}
		// A rejected host key is never a network failure, even if the
		// deadline passed while the connection was being torn down.
		if !hostKeyFailed.Load() && a.network(err) {
			return nil, ErrNetwork
		}
		return nil, fmt.Errorf("SSH handshake or host-key verification failed")
	}
	return &Client{ssh: ssh.NewClient(sshConn, chans, reqs), agent: agentConn}, nil
}

func (c *Client) DialStream(ctx context.Context, target string) (transport.StreamConn, error) {
	if _, _, err := net.SplitHostPort(target); err != nil {
		return nil, fmt.Errorf("invalid SSH destination")
	}
	result := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := c.ssh.Dial("tcp", target)
		result <- struct {
			conn net.Conn
			err  error
		}{conn, err}
	}()
	select {
	case r := <-result:
		if r.err != nil {
			return nil, fmt.Errorf("SSH TCP forwarding failed")
		}
		stream, ok := r.conn.(interface{ CloseWrite() error })
		if !ok {
			r.conn.Close()
			return nil, fmt.Errorf("SSH stream lacks half-close support")
		}
		return streamConn{Conn: r.conn, closeWrite: stream.CloseWrite}, nil
	case <-ctx.Done():
		go func() {
			r := <-result
			if r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

func (c *Client) Close() error {
	var err error
	c.once.Do(func() {
		err = c.ssh.Close()
		if c.agent != nil {
			c.agent.Close()
		}
	})
	return err
}
