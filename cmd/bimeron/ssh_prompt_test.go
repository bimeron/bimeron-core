package main

import (
	"context"
	"errors"
	"io"
	"testing"

	"bimeron/internal/sshtunnel"
)

func TestReadSSHAnswers(t *testing.T) {
	c := sshtunnel.Challenge{Kind: "keyboard_interactive", Prompts: []string{"User", "Password"}, Echo: []bool{true, false}}
	line := func() (string, error) { return "alice", nil }
	secret := func() (string, error) { return "pw", nil }
	answers, err := readSSHAnswers(context.Background(), c, io.Discard, line, secret)
	if err != nil || len(answers) != 2 || answers[0] != "alice" || answers[1] != "pw" {
		t.Fatalf("answers %q err %v", answers, err)
	}

	// An answer typed after the prompt limit expired is refused, and later
	// prompts are not asked.
	ctx, cancel := context.WithCancel(context.Background())
	late := func() (string, error) { cancel(); return "alice", nil }
	asked := false
	answers, err = readSSHAnswers(ctx, c, io.Discard, late, func() (string, error) { asked = true; return "pw", nil })
	if !errors.Is(err, context.Canceled) || answers != nil || asked {
		t.Fatalf("late answers %q err %v asked %v", answers, err, asked)
	}

	ctx, cancel = context.WithCancel(context.Background())
	answers, err = readSSHAnswers(ctx, sshtunnel.Challenge{Prompts: []string{"Password"}, Echo: []bool{false}}, io.Discard, line, func() (string, error) { cancel(); return "pw", nil })
	if err == nil || answers != nil {
		t.Fatalf("late secret %q err %v", answers, err)
	}
}
