package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"bimeron/internal/displaytext"
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

// The terminal prompt shows server text without control characters but keeps
// its line breaks.
func TestReadSSHAnswersFiltersPrompt(t *testing.T) {
	c := sshtunnel.Challenge{Kind: "keyboard_interactive", Prompts: []string{"\x1b]52;c;Zm9v\x07Code\r\nfor alice"}, Echo: []bool{true}}
	var out strings.Builder
	if _, err := readSSHAnswers(context.Background(), c, &out, func() (string, error) { return "1", nil }, nil); err != nil {
		t.Fatal(err)
	}
	if want := string(displaytext.Replacement) + "]52;c;Zm9v" + string(displaytext.Replacement) + "Code\nfor alice: "; out.String() != want {
		t.Fatalf("prompt %q, want %q", out.String(), want)
	}
}
