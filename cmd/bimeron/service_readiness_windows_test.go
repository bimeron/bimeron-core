package main

import (
	"context"
	"net"
	"testing"

	"bimeron/internal/control"
	"bimeron/internal/guard"
)

type panicReadinessListener struct{ net.Listener }

func (panicReadinessListener) Accept() (net.Conn, error) { panic("readiness accept") }
func (panicReadinessListener) Close() error              { return nil }

func TestServiceReadinessPanicUsesCrashBoundary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var caught any
	defer guard.SetRethrow(func(p any) { caught = p })()
	serveServiceReadiness(ctx, control.NewServer(nil), panicReadinessListener{}, cancel)
	if caught != "readiness accept" || ctx.Err() != nil {
		t.Fatal("unexpected readiness crash", caught, ctx.Err())
	}
}
