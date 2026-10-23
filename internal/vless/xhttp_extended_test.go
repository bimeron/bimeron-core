package vless

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

func TestXHTTPExtraRequest(t *testing.T) {
	u, _ := url.Parse("https://example.org/path/")
	options := &accesskey.XHTTPOptions{SessionPlacement: "query", SeqPlacement: "header", UplinkDataPlacement: "header", UplinkChunkSize: accesskey.XHTTPRange{From: 3, To: 3}, XPaddingObfsMode: true, XPaddingPlacement: "cookie", XPaddingBytes: accesskey.XHTTPRange{From: 12, To: 12}}
	req, err := xhttpRequest(t.Context(), "POST", *u, bytes.NewReader([]byte("hello")), "session", "3", "packet-up", options)
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Query().Get("x_session") != "session" || req.Header.Get("X-Seq") != "3" || req.Header.Get("X-Data-0") == "" || req.Header.Get("X-Data-1") == "" {
		t.Fatalf("metadata or payload missing: %v", req)
	}
	if cookie, err := req.Cookie("x_padding"); err != nil || len(cookie.Value) != 12 {
		t.Fatalf("padding cookie: %v %v", cookie, err)
	}
	if req.Body != nil && req.ContentLength > 0 {
		t.Fatal("header payload also sent in body")
	}
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

func TestXHTTPXmuxLimitsAndClose(t *testing.T) {
	var physical atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			physical.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "https://")
	dial := func(ctx context.Context) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) // local test certificate
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return conn, nil
	}
	pool := newXHTTPMuxPool(dial, &accesskey.XHTTPXmux{MaxConnections: accesskey.XHTTPRange{From: 1, To: 1}, MaxConcurrency: accesskey.XHTTPRange{From: 1, To: 1}})
	defer pool.Close()
	first, _ := http.NewRequestWithContext(t.Context(), "GET", server.URL, nil)
	response, err := pool.RoundTrip(first)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	second, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	if _, err := pool.RoundTrip(second); err == nil {
		t.Fatal("concurrency limit ignored")
	}
	_ = response.Body.Close()
	third, _ := http.NewRequestWithContext(t.Context(), "GET", server.URL, nil)
	response, err = pool.RoundTrip(third)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if physical.Load() != 1 {
		t.Fatalf("physical connections: %d", physical.Load())
	}
	pool.Close()
	if _, err := pool.RoundTrip(third); err == nil {
		t.Fatal("closed pool accepted request")
	}
}

func TestXHTTPSeparateDownload(t *testing.T) {
	upload := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("download reached upload endpoint") }))
	defer upload.Close()
	download := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/down/session" {
			t.Errorf("path: %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, "ready")
	}))
	defer download.Close()
	u, _ := url.Parse(upload.URL + "/up/")
	d, _ := url.Parse(download.URL + "/down/")
	ctx, cancel := context.WithCancel(t.Context())
	x := &xhttpConn{ctx: ctx, cancel: cancel, client: upload.Client(), downloadClient: download.Client(), base: *u, downloadBase: *d, session: "session", mode: "packet-up", options: &accesskey.XHTTPOptions{}, ready: make(chan struct{})}
	go x.download(x.downloadURL(), nil)
	defer x.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(x, buf); err != nil || string(buf) != "ready" {
		t.Fatalf("download: %q %v", buf, err)
	}
}
