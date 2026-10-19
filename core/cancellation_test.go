package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"bimeron/internal/accesskey"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type inspectOnlyPlatform struct{ opens atomic.Int32 }

func (p *inspectOnlyPlatform) Acquire(context.Context) (func(), error) { return func() {}, nil }
func (p *inspectOnlyPlatform) Inspect(context.Context, string, bool) (networkPath, error) {
	return networkPath{}, nil
}
func (p *inspectOnlyPlatform) Open(context.Context, SessionConfig, *flowRouter, func(string, string)) (link, error) {
	p.opens.Add(1)
	return nil, fault("unexpected_adapter_setup", false)
}

func TestStopCancelsSSConfHeadersAndBody(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(map[bool]string{false: "headers", true: "body"}[body], func(t *testing.T) {
			entered := make(chan struct{})
			requestCancelled := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if body {
					w.WriteHeader(200)
					w.Write([]byte("ss://"))
					w.(http.Flusher).Flush()
				}
				close(entered)
				<-r.Context().Done()
				close(requestCancelled)
			}))
			defer server.Close()
			p := &inspectOnlyPlatform{}
			e := New(Options{})
			e.factory = func(SessionConfig) backend { return &vpnBackend{platform: p} }
			cfg := testConfig()
			cfg.ResolveOnNetwork = func(ctx context.Context, roundTrip http.RoundTripper) (Profile, error) {
				transport := roundTrip.(*http.Transport)
				transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
				return accesskey.NewResolverWithTransport(transport).Resolve(ctx, "ssconf://"+strings.TrimPrefix(server.URL, "https://"))
			}
			ctx := testDeadline(t)
			defer e.Stop(context.Background())
			if err := e.Start(ctx, cfg); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("request did not start")
			}
			if err := e.Stop(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case <-requestCancelled:
			case <-ctx.Done():
				t.Fatal("ssconf request survived stop")
			}
			if e.Status().State != Disconnected || p.opens.Load() != 0 {
				t.Fatal("network setup occurred after cancellation", e.Status())
			}
		})
	}
}

type blockedReconnect struct {
	entered chan struct{}
	closed  atomic.Int32
}

func (s *blockedReconnect) Wait(context.Context) error { return fault("transport_unavailable", true) }
func (s *blockedReconnect) Suspend()                   {}
func (s *blockedReconnect) Reconnect(ctx context.Context) error {
	close(s.entered)
	<-ctx.Done()
	return ctx.Err()
}
func (s *blockedReconnect) Close() error { s.closed.Add(1); return nil }
func TestStopCancelsReconnectAndCleansLink(t *testing.T) {
	s := &blockedReconnect{entered: make(chan struct{})}
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) { return s, nil }})
	ctx := testDeadline(t)
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.entered:
	case <-time.After(time.Second):
		t.Fatal("reconnect not entered")
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s.closed.Load() != 1 || e.Status().State != Disconnected || e.Status().Session.Active {
		t.Fatal("reconnect cancellation left resources", e.Status())
	}
}
