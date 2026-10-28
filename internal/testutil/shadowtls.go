// Package testutil contains local, opt-in independent-server test fixtures.
package testutil

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

type ShadowServer struct {
	Address     string
	Settings    accesskey.ShadowTLS
	Certificate *x509.Certificate
}

func FreePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// StartShadowTLS runs the unmodified reference executable. The TLS handshake
// target is local and independent of the inner backend, including its name.
func StartShadowTLS(t testing.TB, backend string, shared ...accesskey.ShadowTLS) *ShadowServer {
	t.Helper()
	bin := os.Getenv("BIMERON_SHADOWTLS_BIN")
	if bin == "" {
		t.Skip("set BIMERON_SHADOWTLS_BIN to the official v0.2.25 executable")
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ordinary TLS cover response") }))
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	target.StartTLS()
	t.Cleanup(target.Close)
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	server := &ShadowServer{Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(FreePort(t))),
		Settings: accesskey.ShadowTLS{ServerName: "example.com", Password: hex.EncodeToString(random[:])}, Certificate: target.Certificate()}
	if len(shared) > 0 {
		server.Settings = shared[0]
	}
	cmd := exec.Command(bin, "--threads", "1", "--v3", "--strict", "server", "--listen", server.Address,
		"--server", backend, "--tls", target.Listener.Addr().String(), "--password", server.Settings.Password)
	cmd.Env = append(os.Environ(), "MONOIO_FORCE_LEGACY_DRIVER=1")
	// Reference diagnostics can contain credentials; never publish them.
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return server
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("ShadowTLS reference server did not start")
	return nil
}

func (s *ShadowServer) Wrap(p *accesskey.Profile, roots *x509.CertPool) *x509.CertPool {
	host, port, _ := net.SplitHostPort(s.Address)
	p.TCP.Host, p.UDP.Host = host, host
	p.TCP.Port, _ = strconv.Atoi(port)
	p.UDP.Port = p.TCP.Port
	settings := s.Settings
	p.ShadowTLS = &settings
	if roots == nil {
		roots = x509.NewCertPool()
	} else {
		roots = roots.Clone()
	}
	roots.AddCert(s.Certificate)
	return roots
}

// MaybeShadowTLS lets existing independent inner-server tests run unchanged
// without a wrapper, or exercise the identical matrix through official v3.
func MaybeShadowTLS(t testing.TB, p *accesskey.Profile, roots *x509.CertPool) *x509.CertPool {
	t.Helper()
	if os.Getenv("BIMERON_SHADOWTLS_BIN") == "" {
		return roots
	}
	server := StartShadowTLS(t, net.JoinHostPort(p.TCP.Host, strconv.Itoa(p.TCP.Port)))
	return server.Wrap(p, roots)
}
