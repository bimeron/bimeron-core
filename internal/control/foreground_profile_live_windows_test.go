//go:build windows

package control

import (
	"bimeron/core"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func liveProfileOperation(binary, digest, revision, name, server, action string, self ProcessIdentity) (result string, err error) {
	cmd := exec.Command(binary, "ikev2", "profile-control", "-name", name, "-server", server, "-action", action, "-requester-pid", strconv.FormatUint(uint64(self.PID), 10), "-requester-created", strconv.FormatUint(self.Created, 10))
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Start() != nil {
		return "", fmt.Errorf("profile owner launch failed")
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	client := NewForegroundClient(digest, os.Getenv("BIMERON_IKEV2_FOREGROUND_INSTALLATION"))
	defer client.Close()
	var hello Response
	deadline := time.Now().Add(30 * time.Second)
	for {
		hello, err = client.Call(context.Background(), Request{Version: 1, ID: "hello", Command: "hello"})
		if err == nil {
			break
		}
		select {
		case <-exited:
			return "", fmt.Errorf("profile owner exited before hello")
		default:
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("profile owner startup unknown")
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer func() {
		_, closeErr := client.Call(context.Background(), Request{Version: 1, ID: "close", Command: "close_owner", Instance: hello.Instance})
		if closeErr != nil {
			if err == nil {
				err = fmt.Errorf("profile owner close unknown")
			}
			return
		}
		select {
		case <-exited:
		case <-time.After(20 * time.Second):
			if err == nil {
				err = fmt.Errorf("profile owner exit unknown")
			}
		}
	}()
	if hello.Core == nil || hello.Core.Revision != revision || hello.Core.Modified || hello.Endpoint != "ikev2_profile" {
		return "", fmt.Errorf("profile owner identity mismatch")
	}
	a := hello
	deadline = time.Now().Add(90 * time.Second)
	for a.Operation != "previewed" {
		if a.Operation == "failed" || time.Now().After(deadline) {
			return "", fmt.Errorf("profile preview failed")
		}
		time.Sleep(100 * time.Millisecond)
		a, err = client.Call(context.Background(), Request{Version: 1, ID: "status", Command: "status", Instance: hello.Instance})
		if err != nil {
			return "", fmt.Errorf("profile status unavailable")
		}
	}
	if a.Profile == nil || len(a.Profile.StateToken) != 64 {
		return "", fmt.Errorf("bounded reviewed plan missing")
	}
	token := a.Profile.StateToken
	rejected, _ := client.Call(context.Background(), Request{Version: 1, ID: "changed-plan", Command: action, Instance: hello.Instance, AcceptRevision: revision, PlanToken: "unreviewed"})
	if rejected.Error != "ikev2_profile_preview_required" {
		return "", fmt.Errorf("unreviewed plan accepted")
	}
	a, err = client.Call(context.Background(), Request{Version: 1, ID: "confirm", Command: action, Instance: hello.Instance, AcceptRevision: revision, PlanToken: token})
	if err != nil {
		return "", fmt.Errorf("profile confirmation failed")
	}
	deadline = time.Now().Add(90 * time.Second)
	for a.Operation != "succeeded" {
		if a.Operation == "failed" || time.Now().After(deadline) {
			return "", fmt.Errorf("profile transaction failed or unknown")
		}
		time.Sleep(100 * time.Millisecond)
		a, err = client.Call(context.Background(), Request{Version: 1, ID: "status", Command: "status", Instance: hello.Instance})
		if err != nil {
			return "", fmt.Errorf("profile transaction status unavailable")
		}
	}
	if a.Profile == nil {
		return "", fmt.Errorf("profile receipt missing")
	}
	return a.Profile.Action, nil
}

// Opt-in: creates/removes one uniquely named profile; never authenticates or
// imports credentials/certificates. Interrupted outcomes require manual review.
func TestWindowsForegroundProfileControlLive(t *testing.T) {
	if os.Getenv("BIMERON_IKEV2_FOREGROUND_PROFILE_LIVE") != "1" {
		t.Skip("explicit disposable profile-management fixture required")
	}
	self, release, err := inspectProcess(uint32(os.Getpid()))
	if err != nil || !self.Elevated {
		t.Fatal("protected elevated interactive test identity required")
	}
	defer release()
	binary := os.Getenv("BIMERON_IKEV2_FOREGROUND_BIN")
	files, digest, err := lockImage(binary)
	if err != nil {
		t.Fatal("protected Core required")
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	file, releaseConfig, err := lockForegroundConfig(os.Getenv("BIMERON_IKEV2_TEST_CONFIG"))
	if err != nil {
		t.Fatal("native lab config required")
	}
	defer releaseConfig()
	data, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil {
		t.Fatal("config read failed")
	}
	cfg, err := core.LoadConfigData(data)
	if err != nil || cfg.IKEv2 == nil {
		t.Fatal("native lab config required")
	}
	revision := os.Getenv("BIMERON_IKEV2_FOREGROUND_REVISION")
	name := "Bimeron Foreground IPC " + strconv.FormatInt(time.Now().UnixNano(), 10)
	for _, step := range []struct{ action, want string }{{"apply", "created"}, {"apply", "unchanged"}, {"remove", "removed"}} {
		result, err := liveProfileOperation(binary, digest, revision, name, cfg.IKEv2.ServerName, step.action, self)
		if err != nil || result != step.want {
			t.Fatal("explicit profile fixture failed; inspect owned test profile/journal before further action", err)
		}
	}
}
