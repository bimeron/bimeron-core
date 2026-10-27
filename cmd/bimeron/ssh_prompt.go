package main

import (
	"bufio"
	"context"
	"fmt"
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
	answers := make([]string, len(c.Prompts))
	for i, question := range c.Prompts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fmt.Fprint(os.Stderr, strings.TrimSpace(question), ": ")
		if c.Echo[i] {
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				return nil, fmt.Errorf("SSH authentication input failed")
			}
			answers[i] = strings.TrimRight(line, "\r\n")
		} else {
			secret, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return nil, fmt.Errorf("SSH authentication input failed")
			}
			answers[i] = string(secret)
		}
	}
	return answers, nil
}
