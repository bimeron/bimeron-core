//go:build windows

package main

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func TestWindowsUpdateActionAcceptsFullCommand(t *testing.T) {
	source := filepath.Join(t.TempDir(), "downloaded core.exe")
	digest := strings.Repeat("a", 64)
	expect, updating, err := parseWindowsUpdateAction([]string{"update", "-source", source, "-version", "0.1.0-beta.3", "-sha256", digest})
	if err != nil || !updating || expect.source != source || expect.version != "0.1.0-beta.3" || expect.sha256 != digest {
		t.Fatal("full update invocation was not dispatched", expect, updating, err)
	}
	if _, updating, err := parseWindowsUpdateAction([]string{"update", "-source", source}); !updating || err == nil {
		t.Fatal("incomplete update command accepted")
	}
	if _, updating, err := parseWindowsUpdateAction([]string{"stop", "extra"}); updating || err == nil || err.Error() != "unexpected service arguments" {
		t.Fatal("non-update command accepted extra arguments", err)
	}
	if err := serviceCommand([]string{"update", "-source", "relative", "-version", "0.1.0-beta.3", "-sha256", digest}); err == nil || !strings.Contains(err.Error(), "usage: service update") {
		t.Fatal("update arguments were not parsed before service management", err)
	}
	if err := serviceCommand([]string{"stop", "extra"}); err == nil || err.Error() != "unexpected service arguments" {
		t.Fatal("non-update action accepted extra arguments", err)
	}
}

func TestServiceStopsIdleCore(t *testing.T) {
	requests := make(chan svc.ChangeRequest, 1)
	changes := make(chan svc.Status, 16)
	done := make(chan uint32, 1)
	h := windowsService{listen: func(string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }}
	go func() { _, code := h.Execute(nil, requests, changes); done <- code }()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case status := <-changes:
			if status.State == svc.Running {
				requests <- svc.ChangeRequest{Cmd: svc.Stop}
				goto waiting
			}
		case <-timeout:
			t.Fatal("service did not start")
		}
	}
waiting:
	select {
	case code := <-done:
		if code != 0 {
			t.Fatal(code)
		}
	case <-timeout:
		t.Fatal("service did not stop")
	}
}

func TestWindowsServiceExitClean(t *testing.T) {
	for _, test := range []struct {
		name   string
		status svc.Status
		clean  bool
	}{
		{"clean stop", svc.Status{State: svc.Stopped}, true},
		{"never started since boot", svc.Status{State: svc.Stopped, Win32ExitCode: uint32(windows.ERROR_SERVICE_NEVER_STARTED)}, true},
		{"never started with service code", svc.Status{State: svc.Stopped, Win32ExitCode: uint32(windows.ERROR_SERVICE_NEVER_STARTED), ServiceSpecificExitCode: 1}, false},
		{"service specific failure", svc.Status{State: svc.Stopped, Win32ExitCode: uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR), ServiceSpecificExitCode: 3}, false},
		{"process failure", svc.Status{State: svc.Stopped, Win32ExitCode: uint32(windows.ERROR_PROCESS_ABORTED)}, false},
	} {
		if got := windowsServiceExitClean(test.status); got != test.clean {
			t.Errorf("%s: clean = %v, want %v", test.name, got, test.clean)
		}
	}
}
