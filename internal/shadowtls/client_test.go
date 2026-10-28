package shadowtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bimeron/internal/testutil"
)

func referenceEcho(t testing.TB) (*testutil.ShadowServer, *x509.CertPool) {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	server := testutil.StartShadowTLS(t, echo.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate)
	return server, roots
}

func TestReferenceServer(t *testing.T) {
	server, roots := referenceEcho(t)
	t.Run("LargeReconnectAndSetupCancellation", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			raw, err := net.Dial("tcp", server.Address)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			conn, err := Client(ctx, raw, server.Settings.ServerName, server.Settings.Password, roots)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			data := bytes.Repeat([]byte{0, 255, byte(i), 1, 2, 3}, 30000)
			written := make(chan error, 1)
			go func() { _, err := conn.Write(data); written <- err }()
			got := make([]byte, len(data))
			_, err = io.ReadFull(conn, got)
			if err != nil || !bytes.Equal(data, got) {
				t.Fatalf("large echo: %v", err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
		}
	})
	for _, scenario := range []string{"WrongPassword", "WrongName", "UntrustedCertificate"} {
		t.Run(scenario, func(t *testing.T) {
			password, name, trust := server.Settings.Password, server.Settings.ServerName, roots
			switch scenario {
			case "WrongPassword":
				password += "wrong"
			case "WrongName":
				name = "wrong.invalid"
			case "UntrustedCertificate":
				trust = x509.NewCertPool()
			}
			raw, err := net.Dial("tcp", server.Address)
			if err != nil {
				t.Fatal(err)
			}
			if conn, err := Client(t.Context(), raw, name, password, trust); err == nil {
				_ = conn.Close()
				t.Fatal("unauthenticated peer accepted")
			}
		})
	}
}

// BenchmarkReferenceServer measures local wrapper overhead against the official
// server. Handshake includes TCP connect/authentication/close; the echo case
// reuses one connection and reports one payload's bytes per round trip.
func BenchmarkReferenceServer(b *testing.B) {
	server, roots := referenceEcho(b)
	connect := func(b *testing.B) *Conn {
		b.Helper()
		raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(b.Context(), "tcp", server.Address)
		if err != nil {
			b.Fatal(err)
		}
		conn, err := Client(b.Context(), raw, server.Settings.ServerName, server.Settings.Password, roots)
		if err != nil {
			b.Fatal(err)
		}
		return conn
	}
	b.Run("Handshake", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = connect(b).Close()
		}
	})
	b.Run("RoundTrip64KiB", func(b *testing.B) {
		conn := connect(b)
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		payload, reply := make([]byte, 64*1024), make([]byte, 64*1024)
		b.SetBytes(int64(len(payload)))
		b.ReportAllocs()
		for b.Loop() {
			if _, err := conn.Write(payload); err != nil {
				b.Fatal(err)
			}
			if _, err := io.ReadFull(conn, reply); err != nil {
				b.Fatal(err)
			}
			if !bytes.Equal(reply, payload) {
				b.Fatal("benchmark echo mismatch")
			}
		}
	})
}

func TestCancellation(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if _, err := Client(ctx, left, "example.com", "test-only", nil); err == nil {
		t.Fatal("stalled handshake accepted")
	}
}

func TestOrdinaryTLSAndTLS12NeverBecomeProxyStreams(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			requests := make(chan *http.Request, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- r
				_, _ = io.WriteString(w, "cover response")
			}))
			server.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			raw, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if conn, err := Client(t.Context(), raw, "example.com", "never-send-this-secret", roots); err == nil {
				conn.Close()
				t.Fatal("ordinary TLS peer accepted as ShadowTLS")
			}
			if version == tls.VersionTLS13 {
				select {
				case request := <-requests:
					if request.Method != "GET" || request.URL.Path != "/" || strings.Contains(request.Header.Get("Cookie"), "never-send-this-secret") {
						t.Fatal("invalid ordinary TLS cover request")
					}
				default:
					t.Fatal("authenticated ordinary TLS peer did not receive cover request")
				}
			} else {
				select {
				case <-requests:
					t.Fatal("TLS 1.2-only peer received application data")
				default:
				}
			}
		})
	}
}

type shortConn struct{ net.Conn }

func (c shortConn) Write(p []byte) (int, error) { return c.Conn.Write(p[:min(len(p), 3)]) }

func TestPartialUnderlyingWrites(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(time.Second))
	_ = right.SetDeadline(time.Now().Add(time.Second))
	writer := &Conn{Conn: shortConn{left}, writeMAC: newMAC("secret")}
	reader := &Conn{Conn: right, reader: frameReader{conn: right}, readMAC: newMAC("secret")}
	data := bytes.Repeat([]byte("abc"), maxPayload)
	done := make(chan error, 1)
	go func() { _, err := writer.Write(data); done <- err }()
	got := make([]byte, len(data))
	if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("partial writes: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func testFrame(mac io.Writer, sum func() []byte, body []byte, chained bool) []byte {
	_, _ = mac.Write(body)
	tag := sum()[:tagSize]
	frame := append([]byte{applicationData, 3, 3, 0, 0}, tag...)
	frame = append(frame, body...)
	binary.BigEndian.PutUint16(frame[3:5], uint16(len(body)+tagSize))
	if chained {
		_, _ = mac.Write(tag)
	}
	return frame
}

func TestRecordIntegrityAndResiduals(t *testing.T) {
	for _, scenario := range []string{"Valid", "Tamper", "Replay", "Reorder", "Truncate", "TruncatedHeader", "Oversized", "WrongType", "WrongVersion", "ResidualAfterData"} {
		t.Run(scenario, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			mac := newMAC("secret", []byte("randomS"))
			frame1 := testFrame(mac, func() []byte { return mac.Sum(nil) }, []byte("one"), true)
			frame2 := testFrame(mac, func() []byte { return mac.Sum(nil) }, []byte("two"), true)
			residual := newMAC("secret", []byte("random"))
			noise := testFrame(residual, func() []byte { return residual.Sum(nil) }, []byte("ticket"), false)
			frames := append(append(append([]byte(nil), noise...), frame1...), frame2...)
			switch scenario {
			case "Tamper":
				frames[len(noise)+len(frame1)-1] ^= 1
			case "Replay":
				frames = append(frame1, frame1...)
			case "Reorder":
				frames = append(frame2, frame1...)
			case "Truncate":
				frames = frames[:len(frames)-1]
			case "TruncatedHeader":
				frames = append(append([]byte(nil), frame1...), applicationData, 3)
			case "Oversized":
				frames = []byte{applicationData, 3, 3, 255, 255}
			case "WrongType":
				frames[len(noise)] = 22
			case "WrongVersion":
				frames[len(noise)+2] = 1
			case "ResidualAfterData":
				frames = append(append([]byte(nil), frame1...), noise...)
			}
			go func() {
				defer right.Close()
				for _, b := range frames {
					if _, err := right.Write([]byte{b}); err != nil {
						return
					}
				}
			}()
			conn := &Conn{Conn: left, reader: frameReader{conn: left}, readMAC: newMAC("secret", []byte("randomS")), residual: newMAC("secret", []byte("random"))}
			got, err := io.ReadAll(conn)
			if scenario == "Valid" {
				if err != nil || string(got) != "onetwo" {
					t.Fatalf("valid data: %q, %v", got, err)
				}
				return
			}
			if err == nil || strings.Contains(string(got), "ticket") || string(got) == "onetwo" {
				t.Fatalf("invalid records accepted: %q, %v", got, err)
			}
		})
	}
}

func TestPartialRecordSurvivesTimeout(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	mac := newMAC("secret")
	frame := testFrame(mac, func() []byte { return mac.Sum(nil) }, []byte("payload"), true)
	resume := make(chan struct{})
	go func() { _, _ = right.Write(frame[:7]); <-resume; _, _ = right.Write(frame[7:]) }()
	conn := &Conn{Conn: left, reader: frameReader{conn: left}, readMAC: newMAC("secret")}
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	buffer := make([]byte, 7)
	_, err := conn.Read(buffer)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("expected read timeout: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	close(resume)
	if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != "payload" {
		t.Fatalf("resume: %q %v", buffer, err)
	}
}
