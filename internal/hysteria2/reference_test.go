package hysteria2

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

// Build in a separate module with GOWORK=off: the reference server must not use
// either of Bimeron's patched dependency snapshots.
func referenceServer(t *testing.T) map[string]string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)
	binary := filepath.Join(t.TempDir(), "reference-server.exe")
	cmd := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-o", binary, ".")
	cmd.Dir = "testdata/reference-server"
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "GOWORK=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Env = append(cmd.Env, "GOWORK=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build reference server: %v\n%s", err, b)
	}
	server := exec.CommandContext(ctx, binary)
	stdout, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	var endpoints map[string]string
	if err = json.NewDecoder(stdout).Decode(&endpoints); err != nil {
		t.Fatalf("reference server startup: %v", err)
	}
	return endpoints
}

func TestUnmodifiedReference(t *testing.T) {
	endpoints := referenceServer(t)
	for _, fp := range []string{"firefox", "firefox-116", "firefox-116b", "firefox-116c", "chrome", "chrome-115", "chrome-146"} {
		t.Run(fp, func(t *testing.T) { t.Parallel(); testUnmodifiedReference(t, endpoints, fp) })
	}
}
func testUnmodifiedReference(t *testing.T, endpoints map[string]string, fp string) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(endpoints["certificate"])) {
		t.Fatal("invalid fixture certificate")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	p, err := accesskey.ParseHysteria2("hysteria2://" + endpoints["server"] + "?auth=fixture-pass&sni=localhost&insecure=0&alpn=h3&fp=" + fp)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newClient(ctx, p, net.Dialer{}, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	stream, err := c.DialStream(ctx, endpoints["tcp"])
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte("fixture"), 10000)
	done := make(chan error, 1)
	go func() { _, e := stream.Write(payload); done <- e }()
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, got) {
		t.Fatal("TCP mismatch")
	}
	udp, err := c.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	// This must fragment in both directions, including the 1200-byte Firefox limit.
	payload = bytes.Repeat([]byte("fixture"), 500)
	destination, _ := net.ResolveUDPAddr("udp", endpoints["udp"])
	if _, err = udp.WriteTo(payload, destination); err != nil {
		t.Fatal(err)
	}
	type result struct {
		b   []byte
		err error
	}
	resultCh := make(chan result, 1)
	go func() { b := make([]byte, 4096); n, _, e := udp.ReadFrom(b); b = b[:n]; resultCh <- result{b, e} }()
	select {
	case r := <-resultCh:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if !bytes.Equal(payload, r.b) {
			t.Fatal("UDP mismatch")
		}
	case <-ctx.Done():
		t.Fatal("UDP timeout")
	}
}
