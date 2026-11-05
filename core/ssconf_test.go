package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
