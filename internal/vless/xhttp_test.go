package vless

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestXHTTPPacketUp(t *testing.T) {
	payload := make(chan []byte, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Referer") == "" || !strings.HasPrefix(r.URL.Path, "/stream/session/") && r.URL.Path != "/stream/session" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			payload <- b
			w.WriteHeader(http.StatusOK)
			return
		}
		select {
		case b := <-payload:
			_, _ = w.Write(b)
		case <-r.Context().Done():
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	u, err := url.Parse(server.URL + "/stream/")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	transport := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // test server certificate
	defer transport.CloseIdleConnections()
	x := &xhttpConn{ctx: ctx, cancel: cancel, client: &http.Client{Transport: transport}, base: *u, mode: "packet-up", session: "session", upload: make(chan []byte, 4), ready: make(chan struct{})}
	go x.download(x.sessionURL(""), nil)
	go x.uploadPackets()
	defer x.Close()
	if n, err := x.Write([]byte("xhttp-ok")); err != nil || n != 8 {
		t.Fatalf("write: %d %v", n, err)
	}
	var got [8]byte
	if _, err := io.ReadFull(x, got[:]); err != nil || string(got[:]) != "xhttp-ok" {
		t.Fatalf("read: %q %v", got, err)
	}
}

func TestXHTTPStreamOne(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/grpc" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		var b [4096]byte
		for {
			n, err := r.Body.Read(b[:])
			if n > 0 {
				_, _ = w.Write(b[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	u, err := url.Parse(server.URL + "/stream/")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	transport := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // test server certificate
	defer transport.CloseIdleConnections()
	x := &xhttpConn{ctx: ctx, cancel: cancel, client: &http.Client{Transport: transport}, base: *u, mode: "stream-one", ready: make(chan struct{})}
	x.reader, x.writer = io.Pipe()
	go x.download(x.base, x.reader)
	defer x.Close()
	if n, err := x.Write([]byte("stream-ok")); err != nil || n != 9 {
		t.Fatalf("write: %d %v", n, err)
	}
	var got [9]byte
	if _, err := io.ReadFull(x, got[:]); err != nil || string(got[:]) != "stream-ok" {
		t.Fatalf("read: %q %v", got, err)
	}
}
