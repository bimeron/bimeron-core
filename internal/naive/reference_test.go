package naive

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/proxy"
	"bimeron/internal/telemetry"
	"bimeron/internal/testutil"
)

// TestReferenceServer uses the independent klzgrad/forwardproxy Naive padding
// implementation. Its executable is built separately and is not a core dependency.
func TestReferenceServer(t *testing.T) {
	bin := os.Getenv("BIMERON_NAIVE_CADDY_BIN")
	if bin == "" {
		t.Skip("set BIMERON_NAIVE_CADDY_BIN to Caddy with klzgrad/forwardproxy")
	}
	fixture := httptest.NewTLSServer(nil)
	cert := fixture.Certificate()
	key, err := x509.MarshalPKCS8PrivateKey(fixture.TLS.Certificates[0].PrivateKey)
	fixture.Close()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	config := fmt.Sprintf(`{
 admin off
 auto_https off
 order forward_proxy before file_server
 servers {
  protocols h1 h2
 }
}
:%d {
 bind 127.0.0.1
 tls %q %q
 forward_proxy {
  basic_auth user pass
  hide_ip
  hide_via
  acl {
   allow 127.0.0.1/32
   deny all
  }
 }
}
`, port, filepath.ToSlash(certPath), filepath.ToSlash(keyPath))
	configPath := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "--config", configPath, "--adapter", "caddyfile")
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+dir, "XDG_DATA_HOME="+dir, "APPDATA="+dir)
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reference server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	profile := accesskey.Profile{Type: "naive", TCP: accesskey.Endpoint{Host: "127.0.0.1", Port: port}, Naive: accesskey.Naive{User: "user", Password: "pass", ServerName: "example.com"}}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	roots = testutil.MaybeShadowTLS(t, &profile, roots)
	client, err := New(profile, net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client.rootCAs = roots
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	conn, err := client.DialStream(ctx, echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 10; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 131072+i)
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("reference server payload mismatch")
		}
	}
	t.Run("LocalSOCKS5", func(t *testing.T) {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "through SOCKS5 and NaiveProxy")
		}))
		defer origin.Close()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		serveCtx, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- (&proxy.Server{Proxy: client, Stats: &telemetry.Counters{}}).Serve(serveCtx, listener) }()
		defer func() {
			stop()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}()
		socks := &proxy.SOCKS5{Endpoint: accesskey.Endpoint{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}, Dialer: net.Dialer{Timeout: time.Second}}
		httpTransport := &http.Transport{DialContext: func(ctx context.Context, _, target string) (net.Conn, error) { return socks.DialStream(ctx, target) }}
		defer httpTransport.CloseIdleConnections()
		httpClient := &http.Client{Transport: httpTransport, Timeout: 3 * time.Second}
		resp, err := httpClient.Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil || string(body) != "through SOCKS5 and NaiveProxy" {
			t.Fatalf("SOCKS5 HTTP response: %q, %v", body, err)
		}
	})
}
