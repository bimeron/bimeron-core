package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/ss2022"
	"bimeron/internal/telemetry"
	"bimeron/internal/testutil"
)

func TestShadowTLSShadowsocks(t *testing.T) {
	if os.Getenv("BIMERON_SHADOWTLS_BIN") == "" {
		t.Skip("set BIMERON_SHADOWTLS_BIN and BIMERON_XRAY_BIN")
	}
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			key := make([]byte, 32)
			if method == "2022-blake3-aes-128-gcm" {
				key = key[:16]
			}
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			password := base64.StdEncoding.EncodeToString(key)
			backend := testutil.StartXray(t, "shadowsocks", map[string]any{"method": method, "password": password, "network": "tcp"}, nil)
			server := testutil.StartShadowTLS(t, backend)
			testutil.TrustShadowTLS(t, server)
			p := accesskey.Profile{TCP: accesskey.Endpoint{Cipher: method, Secret: password}}
			server.Wrap(&p, nil)
			dialer, err := OutlineProfile(p, net.Dialer{Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if client, ok := dialer.(*ss2022.Client); ok {
				if packet, err := client.PacketListener().ListenPacket(t.Context()); err == nil {
					_ = packet.Close()
					t.Fatal("native UDP enabled for wrapped profile")
				}
			}
			payload := bytes.Repeat([]byte("binary\x00payload\xff"), 12000)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(payload) }))
			defer origin.Close()
			if method == "aes-256-gcm" {
				wrong := p
				wrong.TCP.Secret += "incorrect"
				badDialer, err := OutlineProfile(wrong, net.Dialer{Timeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				conn, err := badDialer.DialStream(t.Context(), origin.Listener.Addr().String())
				if err == nil {
					_ = conn.SetDeadline(time.Now().Add(time.Second))
					_, _ = io.WriteString(conn, "GET / HTTP/1.0\r\n\r\n")
					var reply [1]byte
					_, err = conn.Read(reply[:])
					_ = conn.Close()
					if err == nil {
						t.Fatal("wrong inner password passed traffic")
					}
				}
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- (&Server{Proxy: dialer, Stats: &telemetry.Counters{}}).Serve(ctx, listener) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			socks := &SOCKS5{Endpoint: accesskey.Endpoint{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}}
			transport := &http.Transport{DialContext: func(ctx context.Context, _, address string) (net.Conn, error) { return socks.DialStream(ctx, address) }}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			for i := 0; i < 2; i++ {
				response, err := client.Get(origin.URL)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || !bytes.Equal(body, payload) {
					t.Fatalf("SOCKS5 large response: %v", err)
				}
			}
		})
	}
}
