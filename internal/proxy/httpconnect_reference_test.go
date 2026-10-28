package proxy

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
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

// Caddy is built separately with the independent forwardproxy implementation;
// it is not linked into the core. CI requires this test with a pinned binary.
func TestReferenceHTTPSConnect(t *testing.T) {
	bin := os.Getenv("BIMERON_HTTP_CADDY_BIN")
	if bin == "" {
		t.Skip("set BIMERON_HTTP_CADDY_BIN to Caddy with forwardproxy")
	}
	cert, roots := httpsCertificate(t, false)
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	config := fmt.Sprintf(`{
 admin off
 auto_https off
 order forward_proxy before file_server
 servers {
  protocols h1
 }
}
:%d {
 bind 127.0.0.1
 tls %q %q
 forward_proxy {
  basic_auth alice secret
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
	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reference proxy did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	p := &HTTPConnect{Endpoint: accesskey.Endpoint{Host: "127.0.0.1", Port: port, Secret: "secret"}, Username: "alice", ServerName: "proxy.example.com", rootCAs: roots, Dialer: net.Dialer{Timeout: time.Second}}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "through verified HTTPS CONNECT")
	}))
	defer origin.Close()
	target := strings.TrimPrefix(origin.URL, "http://")
	for _, credentials := range []string{"missing", "wrong"} {
		t.Run(credentials, func(t *testing.T) {
			bad := *p
			if credentials == "missing" {
				bad.Username, bad.Endpoint.Secret = "", ""
			} else {
				bad.Endpoint.Secret = "wrong"
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			c, err := bad.DialStream(ctx, target)
			if err == nil {
				c.Close()
				t.Fatal("reference proxy accepted invalid credentials")
			}
			if !strings.Contains(err.Error(), "407") {
				t.Fatalf("expected 407: %v", err)
			}
		})
	}
	t.Run("LocalSOCKS5", func(t *testing.T) {
		address, _, _ := start(t, &Server{Proxy: p})
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatal(err)
		}
		endpoint, err := accesskey.ParseSOCKS5("socks5://" + net.JoinHostPort(host, portText))
		if err != nil {
			t.Fatal(err)
		}
		socks := &SOCKS5{Endpoint: endpoint.TCP, Dialer: net.Dialer{Timeout: time.Second}}
		tr := &http.Transport{DialContext: func(ctx context.Context, _, target string) (net.Conn, error) { return socks.DialStream(ctx, target) }}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
		resp, err := client.Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil || string(body) != "through verified HTTPS CONNECT" {
			t.Fatalf("reference response: %q, %v", body, err)
		}
	})
	t.Run("BidirectionalPayload", func(t *testing.T) {
		echo, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer echo.Close()
		done := make(chan error, 1)
		go func() {
			c, err := echo.Accept()
			if err != nil {
				done <- err
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, err = io.Copy(c, c)
			done <- err
		}()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		c, err := p.DialStream(ctx, echo.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		payload := bytes.Repeat([]byte("HTTPS CONNECT tunnel"), 4096)
		if _, err := c.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(payload, got) {
			t.Fatalf("reference tunnel mismatch: %v", err)
		}
		c.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}
