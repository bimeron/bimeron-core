package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"bimeron/internal/sshtunnel"
	"golang.org/x/term"
)

// terminalSSHPrompt is used only for foreground commands, never by the daemon.
func terminalSSHPrompt(ctx context.Context, c sshtunnel.Challenge) ([]string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("SSH authentication requires an interactive terminal or GUI")
	}
	readLine := func() (string, error) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err
	}
	readSecret := func() (string, error) {
		secret, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(secret), err
	}
	return readSSHAnswers(ctx, c, os.Stderr, readLine, readSecret)
}

// readSSHAnswers asks each prompt in turn. The terminal reads cannot be
// interrupted, so an answer typed after ctx ended (the 60-second prompt limit,
// the attempt deadline or Ctrl-C) is discarded and the prompt fails, as before
// the Android bridge made returned answers final (ADR 0036).
func readSSHAnswers(ctx context.Context, c sshtunnel.Challenge, out io.Writer, readLine, readSecret func() (string, error)) ([]string, error) {
	answers := make([]string, len(c.Prompts))
	for i, question := range c.Prompts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fmt.Fprint(out, strings.TrimSpace(question), ": ")
		read := readSecret
		if c.Echo[i] {
			read = readLine
		}
		answer, err := read()
		if err != nil {
			return nil, fmt.Errorf("SSH authentication input failed")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		answers[i] = answer
	}
	return answers, nil
}
