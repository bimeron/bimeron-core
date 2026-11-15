package control

import (
	"bimeron/core"
	"context"
	"net"
	"testing"
	"time"
)

func TestReadinessRejectsCommandsAndRedactsStatus(t *testing.T) {
	server := NewServer(core.New(core.Options{}))
	for _, cmd := range []string{"start", "stop", "shutdown", "auth_reply", "watch", "stats", "capabilities", "version", ""} {
		if a := server.readinessResponse(Request{Version: Version, Command: cmd}); a.Error != "invalid_request" {
			t.Fatal(cmd, a)
		}
	}
	for _, r := range []Request{{Version: 0, Command: "hello"}, {Version: Version, Command: "status", Config: "profile.conf"}, {Version: Version, Command: "hello", Session: "secret"}} {
		if a := server.readinessResponse(r); a.Error != "invalid_request" {
			t.Fatal(a)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.ServeReadiness(ctx, l) }()
	var instance string
	for _, cmd := range []string{"hello", "status"} {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		a, err := exchange(ctx, c, Request{Command: cmd})
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
		if instance != "" && a.Instance != instance {
			t.Fatal("instance changed")
		}
		instance = a.Instance
		if cmd == "hello" && a.Core == nil {
			t.Fatal("missing build")
		}
		if cmd == "status" && (a.Status.State != core.Disconnected || a.Status.Session != nil || a.Status.LastError != "" || a.Owner != nil || a.Events != nil || a.Capabilities != nil) {
			t.Fatal("unexpected readiness payload", a)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not close")
	}
}
