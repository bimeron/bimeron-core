package control

import (
	"context"
	"testing"
	"time"

	"bimeron/internal/sshtunnel"
)

func TestSSHAuthChallengeOneUse(t *testing.T) {
	s := NewServer(&fakeEngine{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan []string, 1)
	go func() {
		a, _ := s.prompt(ctx, sshtunnel.Challenge{Kind: "password", Prompts: []string{"Password"}, Echo: []bool{false}})
		done <- a
	}()
	var challenge *AuthChallenge
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		answer := s.dispatch(context.Background(), Request{Version: Version, Command: "auth_pending"})
		challenge = answer.Auth
		if challenge != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if challenge == nil || challenge.Kind != "password" || len(challenge.Echo) != 1 || challenge.Echo[0] {
		t.Fatal("missing masked password challenge")
	}
	if answer := s.dispatch(context.Background(), Request{Version: Version, Command: "auth_reply", ChallengeID: "wrong", Answers: []string{"secret"}}); answer.Error != "invalid_auth_challenge" {
		t.Fatal(answer.Error)
	}
	if answer := s.dispatch(context.Background(), Request{Version: Version, Command: "auth_reply", ChallengeID: challenge.ID, Answers: []string{"secret"}}); answer.Error != "" || answer.Auth != nil {
		t.Fatal("auth reply exposed challenge or failed")
	}
	select {
	case answers := <-done:
		if len(answers) != 1 || answers[0] != "secret" {
			t.Fatal("answer not delivered")
		}
	case <-time.After(time.Second):
		t.Fatal("prompt did not finish")
	}
	if answer := s.dispatch(context.Background(), Request{Version: Version, Command: "auth_reply", ChallengeID: challenge.ID, Answers: []string{"secret"}}); answer.Error != "invalid_auth_challenge" {
		t.Fatal("challenge reused")
	}
}
