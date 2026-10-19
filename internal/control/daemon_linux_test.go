//go:build linux

package control

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestLinuxDaemonBinary(t *testing.T) {
	binary := os.Getenv("BIMERON_CLI_TEST")
	if binary == "" {
		t.Skip("requires isolated mount and network namespaces")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires namespace root")
	}
	for _, kind := range []string{"mnt", "net"} {
		self, err := os.Readlink("/proc/self/ns/" + kind)
		if err != nil {
			t.Fatal(err)
		}
		host, err := os.Readlink("/proc/1/ns/" + kind)
		if err != nil || self == host {
			t.Fatal("refusing host namespace", kind)
		}
	}
	cmd := exec.Command(binary, "daemon")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		callCtx, end := context.WithTimeout(ctx, 100*time.Millisecond)
		_, err := Call(callCtx, Request{Command: "status"})
		end()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("daemon not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	second := exec.CommandContext(ctx, binary, "daemon")
	out, err := second.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "another Bimeron owner") {
		t.Fatal("duplicate daemon accepted", string(out), err)
	}
	for _, command := range []string{"stop", "status", "shutdown"} {
		if _, err := Call(ctx, Request{Command: command}); err != nil {
			t.Fatal(command, err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("daemon did not exit")
	}
}
