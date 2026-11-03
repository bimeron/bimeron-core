package main

import (
	"bimeron/core"
	"bimeron/internal/control"
	"bimeron/internal/telemetry"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestRepairHelloPreservesCompatibleRelease(t *testing.T) {
	for _, version := range []string{"0.1.0", "0.3.0-beta.2", "99.0.0"} {
		a := control.Response{Version: control.Version, Instance: "instance", Core: &core.BuildDetails{Version: version}}
		if err := validateRepairHello(a); err != nil {
			t.Fatal(version, err)
		}
	}
	for _, a := range []control.Response{{}, {Version: control.Version, Instance: "instance"}, {Version: control.Version + 1, Instance: "instance", Core: &core.BuildDetails{Version: "0.3.0"}}} {
		if validateRepairHello(a) == nil {
			t.Fatal("invalid hello accepted")
		}
	}
}

func TestRepairStatusRequiresAuthoritativeState(t *testing.T) {
	a := control.Response{Version: control.Version, Instance: "instance"}
	if validateRepairStatus(a, "instance") == nil {
		t.Fatal("missing status accepted")
	}
	for _, state := range []core.State{core.Disconnected, core.Connected, core.Connecting, core.Reconnecting} {
		a.Status.State = state
		if err := validateRepairStatus(a, "instance"); err != nil {
			t.Fatal(err)
		}
	}
	a.Status.State = core.Failed
	if validateRepairStatus(a, "instance") == nil {
		t.Fatal("failed status accepted")
	}
	a.Status.State = core.Disconnected
	if validateRepairStatus(a, "another-instance") == nil {
		t.Fatal("changed service instance accepted")
	}
	a.Instance = ""
	if validateRepairStatus(a, "") == nil {
		t.Fatal("absent service instance accepted")
	}
}

type readinessTestEngine struct{ events chan core.Event }

func (*readinessTestEngine) Start(context.Context, core.SessionConfig) error { return nil }
func (*readinessTestEngine) Stop(context.Context) error                      { return nil }
func (*readinessTestEngine) Status() core.Status                             { return core.Status{State: core.Disconnected} }
func (e *readinessTestEngine) Events() <-chan core.Event                     { return e.events }
func (*readinessTestEngine) Stats() telemetry.Snapshot                       { return telemetry.Snapshot{} }

func TestServiceReadinessUsesStandardIPC(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	go func() {
		done <- control.NewServer(&readinessTestEngine{events: make(chan core.Event)}).Serve(ctx, listener)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}()
	call := func(ctx context.Context, request control.Request) (control.Response, error) {
		var response control.Response
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			return response, err
		}
		defer connection.Close()
		deadline, _ := ctx.Deadline()
		connection.SetDeadline(deadline)
		request.Version = control.Version
		if err = json.NewEncoder(connection).Encode(request); err != nil {
			return response, err
		}
		if err = json.NewDecoder(io.LimitReader(connection, 256*1024)).Decode(&response); err != nil {
			return response, err
		}
		if response.Error != "" {
			return response, fmt.Errorf("%s", response.Error)
		}
		return response, nil
	}
	if _, err := call(ctx, control.Request{Command: "status", Instance: "foreground-only"}); err == nil {
		t.Fatal("standard server accepted foreground request field")
	}
	if err := verifyServiceReadiness(ctx, call, validateRepairHello); err != nil {
		t.Fatal("repair readiness rejected actual standard service:", err)
	}
	if err := verifyServiceReadiness(ctx, call, func(hello control.Response) error {
		return validateUpdatedHello(hello, core.GetBuildInfo().Version)
	}); err != nil {
		t.Fatal("update readiness rejected actual standard service:", err)
	}
}
