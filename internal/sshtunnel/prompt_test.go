package sshtunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startInteractiveServer accepts keyboard-interactive authentication when the
// answers equal want, after asking questions with echoes.
func startInteractiveServer(t *testing.T, questions []string, echoes []bool, want []string) (address string, host ssh.PublicKey) {
	t.Helper()
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostKey)
	server := &ssh.ServerConfig{KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		answers, err := challenge("name\x1b[2J", "instruction\x07", questions, echoes)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(answers, want) {
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

// Keyboard-interactive prompts reach every consumer without control or
// bidirectional formatting characters; line breaks and echo flags survive.
func TestKeyboardInteractivePromptsAreSanitized(t *testing.T) {
	rlo := string(rune(0x202E))
	fffd := string(rune(0xFFFD))
	questions := []string{
		"\x1b]52;c;Zm9v\x07Password",
		"Duo two-factor login\r\n\r\n 1. Push\r\n 2. Phone call\r\nPasscode or option (1-2)",
		rlo + "edoc",
		"OTP" + string(rune(0x9b)) + "2J",
	}
	want := []string{
		fffd + "]52;c;Zm9v" + fffd + "Password",
		"Duo two-factor login\n\n 1. Push\n 2. Phone call\nPasscode or option (1-2)",
		fffd + "edoc",
		"OTP" + fffd + "2J",
	}
	echoes := []bool{false, true, false, true}
	answers := []string{"secret", "1", "code", "otp"}
	address, host := startInteractiveServer(t, questions, echoes, answers)
	p := sshProfile(t, address, "", host)
	var seen []Challenge
	prompt := func(_ context.Context, c Challenge) ([]string, error) {
		seen = append(seen, c)
		if c.Kind != "keyboard_interactive" {
			return nil, errors.New("unexpected challenge")
		}
		return answers, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := NewWithOptions(ctx, p, net.Dialer{}, prompt, Options{ProfileOnly: true})
	if err != nil {
		t.Fatal("keyboard-interactive login failed:", err, seen)
	}
	client.Close()
	var interactive []Challenge
	for _, c := range seen {
		if c.Kind == "keyboard_interactive" {
			interactive = append(interactive, c)
		}
	}
	if len(interactive) != 1 {
		t.Fatalf("challenges: %+v", seen)
	}
	if got := interactive[0]; !reflect.DeepEqual(got.Prompts, want) || !reflect.DeepEqual(got.Echo, echoes) {
		t.Fatalf("prompts %q echo %v, want %q %v", got.Prompts, got.Echo, want, echoes)
	}
}
