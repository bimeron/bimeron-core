package streamtransport

import (
	"crypto/x509"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"bimeron/internal/testutil"
)

func TestShadowTLSPreservesSocketControl(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	server := testutil.StartShadowTLS(t, backend.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate)
	var controlled atomic.Int32
	dialer := net.Dialer{Timeout: time.Second, Control: func(string, string, syscall.RawConn) error { controlled.Add(1); return nil }}
	conn, err := Dial(t.Context(), dialer, server.Address, &server.Settings, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil || string(response[:]) != "ping" {
		t.Fatalf("wrapped echo: %v", err)
	}
	wrong := server.Settings
	wrong.Password += "incorrect"
	if failed, err := Dial(t.Context(), dialer, server.Address, &wrong, roots); err == nil {
		failed.Close()
		t.Fatal("wrong wrapper password accepted")
	}
	if controlled.Load() != 2 || accepted.Load() != 1 {
		t.Fatal("socket controls were bypassed or failed authentication reached the backend")
	}
}
