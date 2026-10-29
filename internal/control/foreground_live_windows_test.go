//go:build windows

package control

import (
	"bimeron/core"
	"bimeron/internal/killswitch"
	"context"
	"crypto/sha256"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// Explicit opt-in only: this test changes VPN/routes/DNS/WFP in a disposable VM.
// Both test executable and selected Core must have protected installed identities.
// This elevated harness does NOT establish the medium-to-high UAC UX.
func TestWindowsForegroundLiveLifecycle(t *testing.T) {
	if os.Getenv("BIMERON_IKEV2_FOREGROUND_LIVE") != "1" {
		t.Skip("isolated VM and controlled server required")
	}
	mode := os.Getenv("BIMERON_IKEV2_FOREGROUND_SCENARIO")
	if mode != "" && mode != "bootstrap-stop" && mode != "dns-stop" && mode != "crash" && mode != "retained-refusal" && mode != "dns-modified" {
		t.Fatal("unknown explicit lab scenario")
	}
	binary, path, revision := os.Getenv("BIMERON_IKEV2_FOREGROUND_BIN"), os.Getenv("BIMERON_IKEV2_TEST_CONFIG"), os.Getenv("BIMERON_IKEV2_FOREGROUND_REVISION")
	if binary == "" || path == "" || len(revision) != 40 {
		t.Fatal("exact installed Core, config and reviewed revision required")
	}
	self, releaseSelf, err := inspectProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal("protected test executable required")
	}
	defer releaseSelf()
	if !self.Elevated {
		t.Fatal("elevated interactive disposable account required")
	}
	imageFiles, digest, err := lockImage(binary)
	if err != nil {
		t.Fatal("protected Core executable required")
	}
	defer func() {
		for _, f := range imageFiles {
			f.Close()
		}
	}()
	config, releaseConfig, err := lockForegroundConfig(path)
	if err != nil {
		t.Fatal("safe local test config required")
	}
	defer releaseConfig()
	bytes, err := io.ReadAll(io.LimitReader(config, 64*1024+1))
	if err != nil {
		t.Fatal("config read failed")
	}
	cfg, err := core.LoadConfigData(bytes)
	if err != nil || cfg.IKEv2 == nil {
		t.Fatal("native test configuration required")
	}
	configDigest := fmt.Sprintf("%x", sha256.Sum256(bytes))
	cmd := exec.Command(binary, "ikev2", "foreground", "-config", path, "-sha256", configDigest, "-requester-pid", strconv.FormatUint(uint64(self.PID), 10), "-requester-created", strconv.FormatUint(self.Created, 10))
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Start() != nil {
		t.Fatal("owner launch failed")
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	crashed, expectedTerminalFailure := false, false
	client := NewForegroundClient(digest, os.Getenv("BIMERON_IKEV2_FOREGROUND_INSTALLATION"))
	var hello Response
	var session string
	cleanup := func() {
		defer client.Close()
		if crashed {
			return
		}
		if hello.Instance == "" {
			t.Error("owner outcome unknown; manual VM inspection required")
			return
		}
		deadline := time.Now().Add(120 * time.Second)
		for {
			a, e := client.Call(context.Background(), Request{Version: 1, ID: "cleanup", Command: "stop", Instance: hello.Instance, Session: session})
			if a.Status.Session != nil {
				session = a.Status.Session.ID
			}
			if e == nil || a.Error == "session_stop_failed" {
				break
			}
			if time.Now().After(deadline) {
				t.Error("cleanup unknown; no force-kill or recovery attempted")
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		_, closeErr := client.Call(context.Background(), Request{Version: 1, ID: "close", Command: "close_owner", Instance: hello.Instance, Session: session})
		if closeErr != nil {
			t.Error("owner close outcome unknown")
			return
		}
		select {
		case exitErr := <-exited:
			if exitErr != nil && !expectedTerminalFailure {
				t.Error("owner exited with failure")
			}
		case <-time.After(20 * time.Second):
			t.Error("owner exit timeout; no force-kill attempted")
		}
	}
	t.Cleanup(cleanup)
	deadline := time.Now().Add(30 * time.Second)
	for {
		hello, err = client.Call(context.Background(), Request{Version: 1, ID: "hello", Command: "hello"})
		if err == nil {
			break
		}
		select {
		case <-exited:
			t.Fatal("owner exited before authoritative handshake")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("startup outcome unknown")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if hello.Core == nil || hello.Core.Revision != revision || hello.Core.Modified || hello.Status.Session != nil {
		t.Fatal("identity mismatch or discovery mutated session")
	}
	started := time.Now()
	a, err := client.Call(context.Background(), Request{Version: 1, ID: "activate", Command: "hello", Instance: hello.Instance, AcceptRevision: revision})
	if err != nil || a.Status.Session == nil {
		t.Fatal("activation not accepted")
	}
	session = a.Status.Session.ID
	earlyStop := mode == "bootstrap-stop" || mode == "dns-stop"
	if mode == "bootstrap-stop" {
		time.Sleep(100 * time.Millisecond)
	}
	deadline = time.Now().Add(150 * time.Second)
	for {
		if mode == "bootstrap-stop" {
			break
		}
		if mode == "dns-stop" && a.Status.Native != nil && a.Status.Native.DNS == "installing" {
			break
		}
		if a.Status.State == core.Connected {
			if mode == "dns-stop" || mode == "retained-refusal" {
				t.Fatal("required scenario window/refusal not observed")
			}
			break
		}
		if mode == "retained-refusal" && a.Status.State == core.Failed {
			if a.Status.LastError != "ikev2_existing_kill_switch_requires_recovery" || a.Status.Attempt != 0 || a.Status.Native == nil || !a.Status.Native.RecoveryRequired {
				t.Fatal("retained protection not refused before native open")
			}
			expectedTerminalFailure = true
			t.Log("retained protection refused before native open; explicit recovery still required")
			return
		}
		if a.Status.State == core.Failed || time.Now().After(deadline) {
			t.Fatal("native readiness failed")
		}
		time.Sleep(100 * time.Millisecond)
		a, err = client.Call(context.Background(), Request{Version: 1, ID: "status", Command: "status", Instance: hello.Instance, Session: session})
		if err != nil {
			t.Fatal("status unavailable")
		}
	}
	if !earlyStop {
		if !a.Status.Session.StatsUnavailable {
			t.Fatal("native counters advertised")
		}
		if cfg.IKEv2.KillSwitch && (a.Status.Native == nil || a.Status.Native.WFP != "active" || a.Status.Native.DNS != "active") {
			t.Fatal("premature protected readiness")
		}
		t.Logf("activation-to-connected: %s", time.Since(started))
		client.Close()
		client = NewForegroundClient(digest, os.Getenv("BIMERON_IKEV2_FOREGROUND_INSTALLATION"))
		a, err = client.Call(context.Background(), Request{Version: 1, ID: "reconnect", Command: "hello"})
		if err != nil || a.Status.Session == nil || a.Status.Session.ID != session || a.Instance != hello.Instance {
			t.Fatal("GUI reconnect changed owner/session")
		}
		if mode == "crash" {
			if !cfg.IKEv2.KillSwitch {
				t.Fatal("crash fixture requires native protection")
			}
			// Deliberate failure injection after authoritative protected readiness.
			// This is never a timeout remedy and never touches an unrelated process.
			if cmd.Process.Kill() != nil {
				t.Fatal("deliberate crash injection failed")
			}
			crashed = true
			select {
			case <-exited:
			case <-time.After(20 * time.Second):
				t.Fatal("crash outcome unknown")
			}
			pending, err := killswitch.NativePending()
			if err != nil || !pending {
				t.Fatal("persistent native protection not retained")
			}
			if _, err = client.Call(context.Background(), Request{Version: 1, ID: "after-crash", Command: "status", Instance: hello.Instance, Session: session}); err == nil {
				t.Fatal("crashed owner still reported status")
			}
			t.Log("intentional owner crash retained native WFP; separate explicit VM recovery required")
			return
		}

	}

	if mode == "dns-modified" {
		if !cfg.IKEv2.KillSwitch {
			t.Fatal("modified policy fixture requires protection")
		}
		root, err := windows.GetWindowsDirectory()
		if err != nil {
			t.Fatal("Windows directory unavailable")
		}
		script := `$ErrorActionPreference='Stop'; $tag='BimeronForegroundForeignFixture:f17bf33'; if(@(Get-DnsClientNrptRule|Where-Object Comment -eq $tag).Count -ne 0){throw 'Existing fixture'}; $owned=@(Get-DnsClientNrptRule|Where-Object Comment -match '^BimeronIKEv2DNS:[a-f0-9]{32}$'); if($owned.Count -ne 1){throw 'Ambiguous owned policy'}; Set-DnsClientNrptRule -Name $owned[0].Name -NameServers '127.0.0.2' -ErrorAction Stop; Add-DnsClientNrptRule -Namespace '.bimeron-foreground.invalid' -NameServers '127.0.0.3' -Comment $tag -ErrorAction Stop|Out-Null`
		fixture := exec.Command(root+`\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-Command", script)
		fixture.Stdout = io.Discard
		fixture.Stderr = io.Discard
		if fixture.Run() != nil {
			t.Fatal("controlled policy fixture failed; inspect VM")
		}
	}

	stopped := time.Now()
	deadline = time.Now().Add(120 * time.Second)
	for {
		a, err = client.Call(context.Background(), Request{Version: 1, ID: "stop", Command: "stop", Instance: hello.Instance, Session: session})
		if err == nil {
			break
		}
		if mode == "dns-modified" && a.Error == "session_stop_failed" {
			if a.Status.Session == nil || a.Status.Session.Active || a.Status.Native == nil || a.Status.Native.DNS != "modified" || a.Status.Native.WFP != "retained" || a.Status.Native.RASCleanup != "succeeded" || !a.Status.Native.RecoveryRequired {
				t.Fatal("modified-policy cleanup outcome inconsistent")
			}
			expectedTerminalFailure = true
			t.Log("modified owned DNS refused cleanup; WFP retained; separate explicit recovery required")
			return
		}
		if a.Error != "cleanup_pending" || time.Now().After(deadline) {
			t.Fatal("ordered cleanup did not succeed")
		}
	}
	if a.Status.Session.Active || a.Status.Native == nil || (a.Status.Native.RASCleanup != "succeeded" && !(earlyStop && a.Status.Native.RASCleanup == "not_started")) || a.Status.Native.RecoveryRequired {
		t.Fatal("cleanup outcome inconsistent")
	}
	if cfg.IKEv2.KillSwitch && (a.Status.Native.DNS != "inactive" || a.Status.Native.WFP != "inactive") {
		t.Fatal("owned policy retained after successful cleanup")
	}
	t.Logf("stop-to-cleanup: %s; scenario=%s", time.Since(stopped), mode)
}
