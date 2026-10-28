package ssplugin

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

func referenceBin(t testing.TB, name string) string {
	t.Helper()
	bin := os.Getenv(name)
	if bin == "" {
		if os.Getenv("BIMERON_REQUIRE_SSPLUGIN_INTEROP") == "1" {
			t.Fatalf("%s is required", name)
		}
		t.Skip(name + " is not set")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatal(err)
	}
	return bin
}

func freePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startReference(t testing.TB, bin string, args ...string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "SS_") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	log, err := os.Create(filepath.Join(t.TempDir(), "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			t.Logf("reference server: %s", b)
		}
	})
}

func waitReference(t testing.TB, port int) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("reference server did not become ready")
}

func testCertificate(t testing.TB) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	return certPath, keyPath, roots
}

func referenceProfile(t testing.TB, method string, tlsEnabled bool, mux uint32, paths ...string) (accesskey.Profile, *x509.CertPool, string) {
	t.Helper()
	plugin := referenceBin(t, "BIMERON_V2RAY_PLUGIN_BIN")
	xray := referenceBin(t, "BIMERON_XRAY_BIN")
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	secret := "test-only-plugin-secret"
	if strings.HasPrefix(method, "2022-") {
		key := make([]byte, 32)
		if method == "2022-blake3-aes-128-gcm" {
			key = key[:16]
		}
		rand.Read(key)
		secret = base64.StdEncoding.EncodeToString(key)
	}
	ssPort, pluginPort := freePort(t), freePort(t)
	config := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": ssPort, "protocol": "shadowsocks", "settings": map[string]any{"method": method, "password": secret, "network": "tcp"}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "xray.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	startReference(t, xray, "run", "-config", path)
	waitReference(t, ssPort)
	pathValue := "/transport"
	if len(paths) > 0 {
		pathValue = paths[0]
	}
	args := []string{"-server", "-localAddr", "127.0.0.1", "-localPort", strconv.Itoa(pluginPort), "-remoteAddr", "127.0.0.1", "-remotePort", strconv.Itoa(ssPort), "-path", pathValue, "-loglevel", "none"}
	host := "cloudfront.com"
	var roots *x509.CertPool
	if tlsEnabled {
		cert, key, pool := testCertificate(t)
		roots = pool
		host = "localhost"
		args = append(args, "-tls", "-host", host, "-cert", cert, "-key", key)
	}
	if mux == 0 {
		args = append(args, "-mux", "0")
	}
	startReference(t, plugin, args...)
	waitReference(t, pluginPort)
	options := fmt.Sprintf("v2ray-plugin;path=%s;mux=%d", pathValue, mux)
	if pathValue == "/" && mux == 1 && !tlsEnabled {
		options = "v2ray-plugin"
	}
	if tlsEnabled {
		options += ";tls;host=" + host
	}
	raw := "ss://" + base64.RawURLEncoding.EncodeToString([]byte(method+":"+secret)) + "@127.0.0.1:" + strconv.Itoa(pluginPort) + "/?plugin="
	// QueryEscape is essential: option escapes and URI escapes are separate.
	p, err := accesskey.ParseSS(raw + url.QueryEscape(options))
	if err != nil {
		t.Fatal(err)
	}
	return p, roots, echo.Addr().String()
}

func roundTrip(c net.Conn, data []byte) error {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	written := make(chan error, 1)
	go func() { _, err := io.Copy(c, bytes.NewReader(data)); written <- err }()
	received := make([]byte, len(data))
	_, err := io.ReadFull(c, received)
	if err != nil {
		c.Close()
		<-written
		return err
	}
	if err = <-written; err != nil {
		return err
	}
	if !bytes.Equal(data, received) {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}

func TestOriginalPlugin(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		for _, mode := range []struct {
			tls bool
			mux uint32
		}{{false, 0}, {false, 1}, {false, 8}, {true, 0}, {true, 1}, {true, 8}} {
			t.Run(fmt.Sprintf("%s/tls=%t/mux=%d", method, mode.tls, mode.mux), func(t *testing.T) {
				p, roots, target := referenceProfile(t, method, mode.tls, mode.mux)
				client, err := New(p, net.Dialer{})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				client.SetRootCAs(roots)
				for i := 0; i < 2; i++ {
					conn, err := client.DialStream(context.Background(), target)
					if err != nil {
						t.Fatal(err)
					}
					if err = roundTrip(conn, bytes.Repeat([]byte("plugin-echo"), 14000)); err != nil {
						t.Fatal(err)
					}
					conn.Close()
				}
				if mode.mux > 0 {
					client.mu.Lock()
					connections := len(client.connections)
					client.mu.Unlock()
					if connections != 1 {
						t.Fatalf("sequential requests used %d WebSockets", connections)
					}
				}
			})
		}
	}
}

func TestOriginalPluginConcurrency(t *testing.T) {
	p, roots, target := referenceProfile(t, "aes-256-gcm", true, 8)
	client, err := New(p, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetRootCAs(roots)
	connections := make([]net.Conn, 12)
	for i := range connections {
		conn, err := client.DialStream(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		connections[i] = conn
		defer conn.Close()
	}
	client.mu.Lock()
	count := len(client.connections)
	client.mu.Unlock()
	if count != 2 {
		t.Fatalf("12 sessions with mux=8 used %d WebSockets", count)
	}
	connections[0].Close() // One canceled session must not close its peers.
	var wg sync.WaitGroup
	errs := make(chan error, 11)
	for _, conn := range connections[1:] {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- roundTrip(conn, bytes.Repeat([]byte("concurrent"), 4000)) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestOriginalPluginDefaultsLargeTransferAndReconnect(t *testing.T) {
	p, _, target := referenceProfile(t, "aes-256-gcm", false, 1, "/")
	c, err := New(p, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.DialStream(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = roundTrip(conn, bytes.Repeat([]byte("large-transfer"), 160000)); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	var raw net.Conn
	for ws := range c.connections {
		raw = ws.raw
		break
	}
	c.mu.Unlock()
	if raw == nil {
		t.Fatal("missing transport connection")
	}
	raw.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("closed transport did not terminate its session")
	}
	next, err := c.DialStream(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err = roundTrip(next, []byte("reconnected")); err != nil {
		t.Fatal(err)
	}
}

func TestOriginalPluginTLSFailures(t *testing.T) {
	p, roots, target := referenceProfile(t, "aes-256-gcm", true, 1)
	for _, tc := range []struct {
		name       string
		roots      *x509.CertPool
		host, path string
	}{
		{"untrusted", nil, "localhost", "/transport"},
		{"wrong-name", roots, "wrong.example", "/transport"},
		{"wrong-path", roots, "localhost", "/wrong"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := *p.SSPlugin
			settings.Host, settings.Path = tc.host, tc.path
			p.SSPlugin = &settings
			c, err := New(p, net.Dialer{})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetRootCAs(tc.roots)
			if conn, err := c.DialStream(context.Background(), target); err == nil {
				conn.Close()
				t.Fatal("accepted invalid TLS or WebSocket settings")
			}
		})
	}
}

func BenchmarkOriginalPlugin(b *testing.B) {
	p, roots, target := referenceProfile(b, "aes-256-gcm", true, 8)
	c, err := New(p, net.Dialer{})
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	c.SetRootCAs(roots)
	payload := bytes.Repeat([]byte("x"), 32*1024)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := c.DialStream(context.Background(), target)
		if err != nil {
			b.Fatal(err)
		}
		if err = roundTrip(conn, payload); err != nil {
			b.Fatal(err)
		}
		conn.Close()
	}
}
