package tuic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"github.com/quic-go/quic-go"
)

func testTLS(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func TestLocalPeer(t *testing.T) {
	cert, roots := testTLS(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.CloseWithError(0, "done")
		uni, err := conn.AcceptUniStream(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		var auth [50]byte
		if _, err = io.ReadFull(uni, auth[:]); err != nil {
			serverErr <- err
			return
		}
		if auth[0] != version || auth[1] != 0 {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		state := conn.ConnectionState()
		token, err := state.TLS.ExportKeyingMaterial(string(auth[2:18]), []byte("secret"), 32)
		if err != nil || string(auth[18:]) != string(token) {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		go func() {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				serverErr <- err
				return
			}
			var header [2]byte
			if _, err := io.ReadFull(stream, header[:]); err != nil || header != [2]byte{version, 1} {
				serverErr <- io.ErrUnexpectedEOF
				return
			}
			if _, err := readAddress(stream); err != nil {
				serverErr <- err
				return
			}
			_, err = io.Copy(stream, stream)
			if err != nil {
				serverErr <- err
			}
		}()
		for {
			stream, err := conn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			var header [2]byte
			if _, err := io.ReadFull(stream, header[:]); err != nil {
				serverErr <- err
				return
			}
			if header == [2]byte{version, 3} {
				return
			}
			if header != [2]byte{version, 2} {
				serverErr <- io.ErrUnexpectedEOF
				return
			}
			var packetHeader [8]byte
			if _, err := io.ReadFull(stream, packetHeader[:]); err != nil {
				serverErr <- err
				return
			}
			if packetHeader[4] != 1 || packetHeader[5] != 0 {
				serverErr <- io.ErrUnexpectedEOF
				return
			}
			addr, err := readAddress(stream)
			if err != nil {
				serverErr <- err
				return
			}
			data := make([]byte, binary.BigEndian.Uint16(packetHeader[6:8]))
			if _, err := io.ReadFull(stream, data); err != nil {
				serverErr <- err
				return
			}
			encoded, _ := addressBytes(addr.String())
			for part, payload := range [][]byte{data[:1], data[1:]} {
				out, err := conn.OpenUniStreamSync(ctx)
				if err != nil {
					serverErr <- err
					return
				}
				fragment := packetHeader
				fragment[4], fragment[5] = 2, byte(part)
				binary.BigEndian.PutUint16(fragment[6:8], uint16(len(payload)))
				frame := append([]byte{version, 2}, fragment[:]...)
				if part == 0 {
					frame = append(frame, encoded...)
				} else {
					frame = append(frame, 0xff)
				}
				frame = append(frame, payload...)
				if _, err := out.Write(frame); err != nil {
					serverErr <- err
					return
				}
				_ = out.Close()
			}
		}
	}()
	port := listener.Addr().(*net.UDPAddr).Port
	profile := accesskey.Profile{Type: "tuic", TCP: accesskey.Endpoint{Host: "127.0.0.1", Port: port}, TUIC: accesskey.TUIC{ID: "123e4567-e89b-12d3-a456-426614174000", Password: "secret", ServerName: "localhost", ALPN: "h3"}}
	client, err := New(profile, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	client.rootCAs = roots
	defer client.Close()
	stream, err := client.DialStream(ctx, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err := io.ReadFull(stream, response[:]); err != nil || string(response[:]) != "ping" {
		t.Fatalf("TCP echo: %q, %v", response, err)
	}
	packet, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	_ = packet.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := packet.WriteTo([]byte("dns"), packetAddr(net.JoinHostPort("example.com", strconv.Itoa(53)))); err != nil {
		t.Fatal(err)
	}
	var b [16]byte
	n, from, err := packet.ReadFrom(b[:])
	if err != nil || string(b[:n]) != "dns" || from.String() != "example.com:53" {
		t.Fatalf("UDP echo: %q, %v, %v", b[:n], from, err)
	}
	select {
	case err := <-serverErr:
		t.Fatal(err)
	default:
	}
}

func newLocalClient(t *testing.T, port int, roots *x509.CertPool) *Client {
	t.Helper()
	profile := accesskey.Profile{Type: "tuic", TCP: accesskey.Endpoint{Host: "127.0.0.1", Port: port}, TUIC: accesskey.TUIC{ID: "123e4567-e89b-12d3-a456-426614174000", Password: "secret", ServerName: "localhost", ALPN: "h3"}}
	client, err := New(profile, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	client.rootCAs = roots
	return client
}

func TestStreamCloseDeliversBufferedTail(t *testing.T) {
	cert, roots := testTLS(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type result struct {
		n   int
		err error
	}
	received := make(chan result, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			received <- result{err: err}
			return
		}
		defer conn.CloseWithError(0, "done")
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			received <- result{err: err}
			return
		}
		var header [2]byte
		if _, err := io.ReadFull(stream, header[:]); err != nil {
			received <- result{err: err}
			return
		}
		if _, err := readAddress(stream); err != nil {
			received <- result{err: err}
			return
		}
		// Delay consumption so the tail is still unacknowledged at Close.
		time.Sleep(200 * time.Millisecond)
		data, err := io.ReadAll(stream)
		received <- result{n: len(data), err: err}
	}()
	client := newLocalClient(t, listener.Addr().(*net.UDPAddr).Port, roots)
	defer client.Close()
	stream, err := client.DialStream(ctx, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4<<20)
	go func() {
		if _, err := stream.Write(payload); err != nil {
			t.Error(err)
		}
		_ = stream.CloseWrite()
		_ = stream.Close()
	}()
	select {
	case r := <-received:
		if r.err != nil || r.n != len(payload) {
			t.Fatalf("server received %d of %d bytes: %v", r.n, len(payload), r.err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for server")
	}
}

func TestCloseDoesNotWaitForInFlightConnect(t *testing.T) {
	// A UDP socket that never answers keeps the QUIC handshake pending.
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	client := newLocalClient(t, blackhole.LocalAddr().(*net.UDPAddr).Port, nil)
	dialed := make(chan error, 1)
	go func() {
		_, err := client.DialStream(context.Background(), "example.com:443")
		dialed <- err
	}()
	_ = blackhole.SetReadDeadline(time.Now().Add(5 * time.Second))
	var b [2048]byte
	if _, _, err := blackhole.ReadFrom(b[:]); err != nil {
		t.Fatalf("handshake did not start: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind an in-flight connect")
	}
	select {
	case err := <-dialed:
		if err == nil {
			t.Fatal("DialStream succeeded after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel the in-flight connect")
	}
	if _, err := client.ListenPacket(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ListenPacket after Close: %v", err)
	}
}
