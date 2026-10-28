package testutil

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// StartXray starts a separate reference process, never a compiled dependency.
func StartXray(t testing.TB, protocol string, settings, streamSettings map[string]any) string {
	t.Helper()
	bin := os.Getenv("BIMERON_XRAY_BIN")
	if bin == "" {
		t.Skip("set BIMERON_XRAY_BIN for independent interoperability")
	}
	port := FreePort(t)
	inbound := map[string]any{"listen": "127.0.0.1", "port": port, "protocol": protocol, "settings": settings}
	if streamSettings != nil {
		inbound["streamSettings"] = streamSettings
	}
	config := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{inbound}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "xray.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-config", path)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		conn, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return address
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("independent Xray server did not start")
	return ""
}

// TrustShadowTLS configures the test process's system trust before its first
// system-pool lookup. httptest uses the same public test certificate per process.
// Other fixtures should pass an explicit pool when one is already available.
func TrustShadowTLS(t testing.TB, server *ShadowServer) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shadowtls-ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate.Raw})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", path)
}
