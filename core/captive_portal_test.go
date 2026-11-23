package core

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCaptivePortalClearsDuringHeldFailure(t *testing.T) {
	var onNewNetwork atomic.Bool
	e := New(Options{})
	e.protected = true
	e.status.State = Failed
	e.pollEvery = time.Millisecond
	e.network = func() string {
		if onNewNetwork.Load() {
			return "new"
		}
		return "original"
	}
	e.beginPortalAttempt("original")()
	if got := e.Status().NetworkHint; got != captivePortalHint {
		t.Fatalf("NetworkHint = %q", got)
	}
	stop := e.watchPortalNetwork(t.Context())
	defer stop()
	onNewNetwork.Store(true)
	timeout := time.After(time.Second)
	for {
		select {
		case <-timeout:
			t.Fatal("network change did not clear the hint")
		case <-e.events:
			status := e.Status()
			if status.NetworkHint == "" {
				if status.State != Failed {
					t.Fatalf("state changed to %s", status.State)
				}
				return
			}
		}
	}
}

func TestCaptivePortalStatusAndEvents(t *testing.T) {
	local := "network A"
	e := &Engine{
		protected: true,
		network:   func() string { return local },
		status:    Status{State: Connecting},
		events:    make(chan Event, 16),
	}
	checkStatus := func(want bool) {
		t.Helper()
		data, err := json.Marshal(e.Status())
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		value, present := fields["NetworkHint"]
		if present != want || want && string(value) != `"captive_portal"` {
			t.Fatalf("NetworkHint present = %v, value = %s", present, value)
		}
	}
	countEvents := func(want int) {
		t.Helper()
		count := 0
		for len(e.events) > 0 {
			if (<-e.events).Code == "captive_portal_suspected" {
				count++
			}
		}
		if count != want {
			t.Fatalf("captive portal events = %d, want %d", count, want)
		}
	}
	checkStatus(false)
	attemptA := e.beginPortalAttempt("path A")
	attemptA()
	e.beginPortalAttempt("path A")()
	checkStatus(true)
	countEvents(1)

	e.transition(Connected, nil)
	checkStatus(false)
	e.transition(Reconnecting, nil)
	e.beginPortalAttempt("path A")()
	checkStatus(true)
	countEvents(0)

	local = "network B"
	e.observePortalNetwork()
	attemptA()
	checkStatus(false)
	e.beginPortalAttempt("path B")()
	checkStatus(true)
	countEvents(1)

	// A gateway or DNS change may change the inspected path while the
	// local interface address is unchanged.
	e.beginPortalAttempt("new path B")
	checkStatus(false)
	e.beginPortalAttempt("new path B")()
	countEvents(1)
	e.transition(Stopping, nil)
	checkStatus(false)
	e.stopRequested = true
	e.beginPortalAttempt("new path B")()
	checkStatus(false)
	countEvents(0)
}

func TestCaptivePortalPhysicalHandshake(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		tls, suspected bool
	}{
		{"plaintext in TLS", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", true, true},
		{"proxy redirect", "HTTP/1.1 302 Found\r\nLocation: http://login.test/\r\n\r\n", false, true},
		{"proxy credentials", "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", false, false},
		{"downstream response", "HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				// Consume the existing handshake before replying.
				var b [1]byte
				if _, err := io.ReadFull(conn, b[:]); err != nil {
					done <- err
					return
				}
				_, err = io.WriteString(conn, tc.response)
				if err == nil {
					// Drain the rest of the request before closing, so the
					// peer receives the response without a TCP reset.
					_, _ = io.Copy(io.Discard, conn)
				}
				done <- err
			}()
			cfg := DefaultConfig()
			cfg.Resolve = func(context.Context) (Profile, error) {
				p := Profile{Type: "http", TCP: Endpoint{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}}
				if tc.tls {
					p.HTTPServerName = "upstream.test"
				}
				return p, nil
			}
			suspected := false
			cfg.portalAttempt = func(string) func() { return func() { suspected = true } }
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, _, _, _, err = prepareVPN(ctx, ctx, cfg, networkPath{}, func(string, string) {}, nil)
			if err == nil || !strings.Contains(err.Error(), "transport_check_failed") {
				t.Fatalf("prepareVPN error = %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if suspected != tc.suspected {
				t.Fatalf("suspected = %v, want %v", suspected, tc.suspected)
			}
		})
	}
}

func TestCaptivePortalCertificateForAnotherName(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("TLS verification allowed a request to the server")
	}))
	defer server.Close()
	cfg := DefaultConfig()
	cfg.Resolve = func(context.Context) (Profile, error) {
		port := server.Listener.Addr().(*net.TCPAddr).Port
		return Profile{Type: "http", HTTPServerName: "wrong-name.test", TCP: Endpoint{Host: "127.0.0.1", Port: port}}, nil
	}
	suspected := false
	cfg.portalAttempt = func(string) func() { return func() { suspected = true } }
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, _, _, _, err := prepareVPN(ctx, ctx, cfg, networkPath{}, func(string, string) {}, nil)
	if err == nil || !suspected {
		t.Fatalf("unexpected TLS result: error = %v, suspected = %v", err, suspected)
	}
}
