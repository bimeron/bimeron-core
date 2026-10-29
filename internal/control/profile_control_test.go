package control

import (
	"bimeron/core"
	"bimeron/internal/systemvpn"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProfileControlRequiresExactPreviewAndOneExplicitConfirmation(t *testing.T) {
	s := NewServer(&fakeEngine{})
	s.build = func() core.BuildDetails { return core.BuildDetails{Revision: strings.Repeat("a", 40)} }
	var mutations atomic.Int32
	release := make(chan struct{})
	wait := s.bindProfileControl(systemvpn.Config{}, false, func(systemvpn.Config) (systemvpn.ProfilePlan, error) {
		return systemvpn.ProfilePlan{StateToken: "reviewed"}, nil
	}, func(_ systemvpn.Config, remove bool, token string) (systemvpn.ProfilePlan, error) {
		mutations.Add(1)
		if token != "reviewed" || remove {
			t.Error("unreviewed mutation")
		}
		<-release
		return systemvpn.ProfilePlan{Action: "created"}, nil
	})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer func() { unblock(); wait() }()
	call := func(command, token string) Response {
		r := Request{Version: 1, ID: "x", Command: command, Instance: s.instance, PlanToken: token}
		if command == "apply" || command == "remove" {
			r.AcceptRevision = strings.Repeat("a", 40)
		}
		return s.foregroundDispatch(context.Background(), r)
	}
	hello := Request{Version: 1, ID: "hello", Command: "hello"}
	s.foregroundDispatch(context.Background(), hello)
	deadline := time.Now().Add(time.Second)
	for call("status", "").Operation != "previewed" {
		if time.Now().After(deadline) {
			t.Fatal("preview stuck")
		}
		time.Sleep(time.Millisecond)
	}
	if mutations.Load() != 0 {
		t.Fatal("preview mutated system")
	}
	if call("apply", "changed").Error != "ikev2_profile_preview_required" {
		t.Fatal("changed preview accepted")
	}
	if a := call("apply", "reviewed"); a.Error != "" || a.Operation != "applying" {
		t.Fatal(a)
	}
	if call("close_owner", "").Error != "operation_pending" {
		t.Fatal("closed active transaction")
	}
	if call("apply", "reviewed").Error != "ikev2_profile_preview_required" {
		t.Fatal("duplicate confirmation accepted")
	}
	unblock()
	wait()
	if a := call("status", ""); a.Operation != "succeeded" || a.Profile.Action != "created" || mutations.Load() != 1 {
		t.Fatal(a)
	}
}

func TestProfileControlErrorsAreSafe(t *testing.T) {
	if safeProfileCode(errors.New("ikev2_private_secret")) != "ikev2_profile_operation_failed" {
		t.Fatal("secret escaped")
	}
	if safeProfileCode(errors.New("ikev2_profile_preview_changed")) != "ikev2_profile_preview_changed" {
		t.Fatal("safe error lost")
	}
}
