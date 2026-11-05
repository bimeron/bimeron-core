package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestResolveSSConfTrustedHTTPS(t *testing.T) {
	const body = "ss://aes-128-gcm:secret@127.0.0.1:443"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	got, err := resolveSSConf(context.Background(), strings.Replace(server.URL, "https:", "ssconf:", 1), PacketNetwork{}, &tls.Config{RootCAs: roots})
	if err != nil || string(got) != body {
		t.Fatalf("result %q: %v", got, err)
	}
}

func TestResolveSSConfRedirectControls(t *testing.T) {
	const body = "ss://aes-128-gcm:secret@127.0.0.1:443"
	end := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	defer end.Close()
	start := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, end.URL, http.StatusFound) }))
	defer start.Close()
	roots := x509.NewCertPool()
	roots.AddCert(start.Certificate())
	roots.AddCert(end.Certificate())
	var calls atomic.Int32
	network := PacketNetwork{Dialer: net.Dialer{Control: func(network, address string, raw syscall.RawConn) error { calls.Add(1); return nil }}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := resolveSSConf(ctx, strings.Replace(start.URL, "https:", "ssconf:", 1), network, &tls.Config{RootCAs: roots})
	if err != nil || string(got) != body {
		t.Fatalf("result %q: %v", got, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("controls = %d, want 2", calls.Load())
	}
}

func TestResolveSSConfBodyCancellation(t *testing.T) {
	entered := make(chan struct{})
	stopped := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(stopped)
		w.Write([]byte("ss://aes-128-gcm:secret@"))
		w.(http.Flusher).Flush()
		close(entered)
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		got, err := resolveSSConf(ctx, strings.Replace(server.URL, "https:", "ssconf:", 1), PacketNetwork{}, &tls.Config{RootCAs: roots})
		if got != nil || err == nil {
			t.Errorf("canceled body result %q: %v", got, err)
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("body not started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("body cancellation stalled")
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("server context not canceled")
	}
}
