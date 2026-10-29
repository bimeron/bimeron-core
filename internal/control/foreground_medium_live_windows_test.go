//go:build windows

package control

import (
	"bimeron/core"
	"bimeron/internal/windowsnet"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// The privileged lab orchestrator starts the owner with this test process's
// PID/creation time. No UAC prompt is bypassed or claimed as tested here.
func TestWindowsForegroundMediumClientLive(t *testing.T) {
	mode := os.Getenv("BIMERON_IKEV2_FOREGROUND_CLIENT_MODE")
	if mode != "medium" && mode != "medium-exit" && mode != "medium-reopen" && mode != "high-idle-cleanup" {
		t.Skip("explicit disposable-VM client fixture required")
	}
	self, release, err := inspectProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal("protected interactive test identity required")
	}
	defer release()
	if (mode != "high-idle-cleanup" && self.Elevated) || (mode == "high-idle-cleanup" && !self.Elevated) {
		t.Fatal("unexpected integrity/elevation")
	}
	files, digest, err := lockImage(os.Getenv("BIMERON_IKEV2_FOREGROUND_BIN"))
	if err != nil {
		t.Fatal("protected selected Core required")
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	client := NewForegroundClient(digest, os.Getenv("BIMERON_IKEV2_FOREGROUND_INSTALLATION"))
	defer client.Close()
	var hello Response
	deadline := time.Now().Add(45 * time.Second)
	for {
		hello, err = client.Call(context.Background(), Request{Version: 1, ID: "medium-hello", Command: "hello"})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("authenticated owner unavailable")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if hello.Core == nil || hello.Core.Modified || hello.Core.Revision != os.Getenv("BIMERON_IKEV2_FOREGROUND_REVISION") {
		t.Fatal("identity mismatch or discovery mutated networking")
	}

	if mode == "medium-reopen" {
		data, err := os.ReadFile(os.Getenv("BIMERON_IKEV2_FOREGROUND_RECEIPT"))
		if err != nil || len(data) > 4096 {
			t.Fatal("prior GUI identity receipt unavailable")
		}
		var previous struct {
			Instance, Session string
			Owner             *ProcessIdentity
		}
		if json.Unmarshal(data, &previous) != nil || previous.Owner == nil || hello.Owner == nil || *previous.Owner != *hello.Owner || hello.Instance != previous.Instance || hello.Status.Session == nil || hello.Status.Session.ID != previous.Session || hello.Status.State != core.Connected {
			t.Fatal("reopened GUI did not find the same active owner")
		}
		deadline := time.Now().Add(120 * time.Second)
		for {
			stopped, e := client.Call(context.Background(), Request{Version: 1, ID: "reopened-stop", Command: "stop", Instance: hello.Instance, Session: previous.Session})
			if e == nil {
				if stopped.Status.Session.Active || stopped.Status.Native == nil || stopped.Status.Native.RASCleanup != "succeeded" || stopped.Status.Native.WFP != "inactive" || stopped.Status.Native.DNS != "inactive" {
					t.Fatal("reopened GUI cleanup incomplete")
				}
				break
			}
			if stopped.Error != "cleanup_pending" || time.Now().After(deadline) {
				t.Fatal("reopened GUI cleanup failed or unknown")
			}
		}
		if _, err := client.Call(context.Background(), Request{Version: 1, ID: "reopened-close", Command: "close_owner", Instance: hello.Instance, Session: previous.Session}); err != nil {
			t.Fatal("reopened owner close failed")
		}
		return
	}
	if hello.Status.Session != nil || hello.Status.State != core.Disconnected {
		t.Fatal("initial discovery mutated networking")
	}
	if mode == "medium" || mode == "medium-exit" {
		if release, err := windowsnet.Acquire(); err == nil {
			release()
			t.Fatal("idle owner did not block another network owner")
		}
		a, _ := client.Call(context.Background(), Request{Version: 1, ID: "stale", Command: "status", Instance: "stale-instance"})
		if a.Error != "stale_instance" {
			t.Fatal("stale instance accepted")
		}
		a, _ = client.Call(context.Background(), Request{Version: 1, ID: "forbidden", Command: "start", Instance: hello.Instance})
		if a.Error != "unknown_command" {
			t.Fatal("packet start accepted")
		}
	}

	if mode == "medium-exit" {
		a, e := client.Call(context.Background(), Request{Version: 1, ID: "medium-activate", Command: "hello", Instance: hello.Instance, AcceptRevision: hello.Core.Revision})
		if e != nil || a.Status.Session == nil {
			t.Fatal("medium activation failed")
		}
		session := a.Status.Session.ID
		deadline := time.Now().Add(150 * time.Second)
		for a.Status.State != core.Connected {
			if a.Status.State == core.Failed || time.Now().After(deadline) {
				t.Fatal("medium native readiness failed")
			}
			time.Sleep(100 * time.Millisecond)
			a, e = client.Call(context.Background(), Request{Version: 1, ID: "medium-status", Command: "status", Instance: hello.Instance, Session: session})
			if e != nil {
				t.Fatal("medium native status unavailable")
			}
		}
		if a.Status.Native == nil || a.Status.Native.WFP != "active" || a.Status.Native.DNS != "active" {
			t.Fatal("medium protected readiness premature")
		}
		receipt, _ := json.Marshal(struct {
			Instance, Session string
			Owner             *ProcessIdentity
		}{hello.Instance, session, hello.Owner})
		if os.WriteFile(os.Getenv("BIMERON_IKEV2_FOREGROUND_RECEIPT"), receipt, 0600) != nil {
			t.Fatal("GUI identity receipt failed")
		}
		t.Log("medium GUI process exits intentionally without stop; owner must remain alive")
		return
	}
	if _, err = client.Call(context.Background(), Request{Version: 1, ID: "close-idle", Command: "close_owner", Instance: hello.Instance}); err != nil {
		t.Fatal("idle owner close failed")
	}
}
