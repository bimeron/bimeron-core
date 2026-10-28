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

func expand(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("SSH home directory unavailable")
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func signer(path string, ctx context.Context, prompt Prompt) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
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
	if err := p.ValidateShadowTLS(); err != nil {
		return nil, err
	}
	if p.Type != "ssh" || p.SSH.User == "" || p.TCP.Host == "" || p.TCP.Port < 1 || p.TCP.Port > 65535 {
		return nil, fmt.Errorf("invalid SSH profile")
	}
	hostFile, err := expand(p.SSH.KnownHostsFile)
	if err != nil {
		return nil, err
	}
	if hostFile == "" {
		if !defaultKeys {
			return nil, fmt.Errorf("SSH known_hosts file must be selected for service use")
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("SSH known_hosts unavailable")
		}
		hostFile = filepath.Join(home, ".ssh", "known_hosts")
	}
	verify, err := knownhosts.New(hostFile)
	if err != nil {
		return nil, fmt.Errorf("SSH known_hosts unavailable")
	}
	identity, err := expand(p.SSH.IdentityFile)
	if err != nil {
		return nil, err
	}
	var methods []ssh.AuthMethod
	if identity != "" {
		s, err := signer(identity, ctx, prompt)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(s))
	}
	agentConn, err := dialAgent(ctx)
	if err == nil {
		if signers, e := agent.NewClient(agentConn).Signers(); e == nil && len(signers) > 0 {
			methods = append(methods, ssh.PublicKeys(signers...))
		} else {
			agentConn.Close()
			agentConn = nil
		}
	}
	if identity == "" && defaultKeys {
		if home, e := os.UserHomeDir(); e == nil {
			for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
				path := filepath.Join(home, ".ssh", name)
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
	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := streamtransport.Dial(dialCtx, dialer, address, p.ShadowTLS, nil)
	if err != nil {
		if agentConn != nil {
			agentConn.Close()
		}
		return nil, fmt.Errorf("SSH server unavailable")
	}
	stop := context.AfterFunc(dialCtx, func() { _ = conn.Close() })
	config := &ssh.ClientConfig{User: p.SSH.User, Auth: methods, HostKeyCallback: verify, Timeout: 20 * time.Second}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	stop()
	if err != nil {
		conn.Close()
		if agentConn != nil {
			agentConn.Close()
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
