package tuic

import (
	"bytes"
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
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/vpn"
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

func TestDNSExchangeWithNoDissociateStreamCredit(t *testing.T) {
	for _, outcome := range []string{"answer", "refused", "deadline"} {
		t.Run(outcome, func(t *testing.T) {
			cert, roots := testTLS(t)
			listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true, MaxIncomingUniStreams: 1})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			client := newLocalClient(t, listener.Addr().(*net.UDPAddr).Port, roots)
			defer client.Close()
			session, _, err := client.acquire(ctx, false)
			if err != nil {
				t.Fatal(err)
			}
			client.release(session)
			peer, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			auth, err := peer.AcceptUniStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, auth); err != nil {
				t.Fatal(err)
			}
			query := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
			answer := append([]byte(nil), query...)
			answer[2] |= 0x80
			if outcome == "refused" {
				answer[3] = 5
			}
			r := vpn.DNSResolver{Servers: []string{"192.0.2.1"}, UDP: client, TCP: client, Timeout: 350 * time.Millisecond}
			type result struct {
				data []byte
				err  error
			}
			done := make(chan result, 1)
			go func() { b, err := r.Exchange(ctx, query, false); done <- result{b, err} }()
			packet, err := peer.AcceptUniStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Leave the query unread to hold the only incoming stream credit.
			var hdr [10]byte
			if _, err := io.ReadFull(packet, hdr[:]); err != nil {
				t.Fatal(err)
			}
			addr, err := readAddress(packet)
			if err != nil {
				t.Fatal(err)
			}
			if outcome != "deadline" {
				out, err := peer.OpenUniStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := addressBytes(addr.String())
				if err != nil {
					t.Fatal(err)
				}
				frame := append(hdr[:], encoded...)
				if _, err := out.Write(append(frame, answer...)); err != nil {
					t.Fatal(err)
				}
				if err := out.Close(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case got := <-done:
				switch outcome {
				case "answer":
					if got.err != nil || !bytes.Equal(got.data, answer) {
						t.Fatalf("answer %x, %v", got.data, got.err)
					}
				case "refused":
					if got.err == nil || !strings.Contains(got.err.Error(), "UDP response failed") {
						t.Fatalf("fallback error: %v", got.err)
					}
				case "deadline":
					if got.err == nil || !strings.Contains(got.err.Error(), "UDP read timeout") {
						t.Fatalf("deadline error: %v", got.err)
					}
				}
			case <-time.After(700 * time.Millisecond):
				t.Fatal("DNS delivery or fallback blocked on dissociation credit")
			}
			if outcome != "answer" {
				// Exercise TCP fallback while the peer still holds UDP stream credit.
				answer[3] = 0
				go func() {
					b, err := r.Exchange(ctx, query, true)
					done <- result{b, err}
				}()
				tcp, err := peer.AcceptStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				_ = tcp.SetDeadline(time.Now().Add(time.Second))
				address, err := addressBytes("192.0.2.1:53")
				if err != nil {
					t.Fatal(err)
				}
				want := append([]byte{version, 1}, address...)
				want = binary.BigEndian.AppendUint16(want, uint16(len(query)))
				want = append(want, query...)
				got := make([]byte, len(want))
				if _, err := io.ReadFull(tcp, got); err != nil || !bytes.Equal(got, want) {
					t.Fatalf("TCP query %x, %v", got, err)
				}
				frame := binary.BigEndian.AppendUint16(nil, uint16(len(answer)))
				if _, err := tcp.Write(append(frame, answer...)); err != nil {
					t.Fatal(err)
				}
				if err := tcp.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case got := <-done:
					if got.err != nil || !bytes.Equal(got.data, answer) {
						t.Fatalf("TCP answer %x, %v", got.data, got.err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if _, err := io.Copy(io.Discard, packet); err != nil {
				t.Fatal(err)
			}
			control, err := peer.AcceptUniStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := control.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(io.LimitReader(control, 5))
			want := []byte{version, 3, hdr[2], hdr[3]}
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("Dissociate = %x, %v; want %x", got, err, want)
			}
			client.mu.Lock()
			defer client.mu.Unlock()
			if len(session.packets) != 0 {
				t.Fatal("association still registered after exchange")
			}
		})
	}
}

func associationTestPeer(t *testing.T, credit int64) (context.Context, *Client, *quic.Listener) {
	t.Helper()
	cert, roots := testTLS(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true, MaxIncomingUniStreams: credit})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	client := newLocalClient(t, listener.Addr().(*net.UDPAddr).Port, roots)
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx, client, listener
}

func openAssociation(t *testing.T, ctx context.Context, client *Client) *packetConn {
	t.Helper()
	p, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*packetConn)
}

func TestMoreThan256LiveAssociations(t *testing.T) {
	ctx, client, listener := associationTestPeer(t, 0)
	var live []*packetConn
	seen := make(map[uint16]bool)
	for i := 0; i < 300; i++ {
		p := openAssociation(t, ctx, client)
		if seen[p.id] {
			t.Fatalf("duplicate live ID %d", p.id)
		}
		seen[p.id] = true
		live = append(live, p)
	}
	peer, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := peer.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, auth); err != nil {
		t.Fatal(err)
	}
	target := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
	for _, p := range live {
		if _, err := p.WriteTo([]byte{42}, target); err != nil {
			t.Fatal(err)
		}
		stream, err := peer.AcceptUniStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := io.ReadAll(stream)
		if err != nil || len(frame) < 11 || frame[1] != 2 || binary.BigEndian.Uint16(frame[2:4]) != p.id || frame[len(frame)-1] != 42 {
			t.Fatalf("association %d delivered %x, %v", p.id, frame, err)
		}
	}
}

func TestAssociationRotationDrainsOriginalPeer(t *testing.T) {
	ctx, client, listener := associationTestPeer(t, 1)
	old := openAssociation(t, ctx, client)
	accept := func() *quic.Conn {
		t.Helper()
		conn, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	original := accept()
	// Leave authentication unread to hold the sole control-stream credit.
	auth, err := original.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := client.DialStream(ctx, "192.0.2.1:53")
	if err != nil {
		t.Fatal(err)
	}
	serverTCP, err := original.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Skip the intermediate IDs, then issue the final ID through ListenPacket.
	client.mu.Lock()
	old.session.nextID = associationIDs - 1
	client.mu.Unlock()
	last := openAssociation(t, ctx, client)
	if last.id != 0 || last.session != old.session {
		t.Fatal("last ID was not issued on original connection")
	}
	if err := last.Close(); err != nil {
		t.Fatal(err)
	}
	fresh := openAssociation(t, ctx, client)
	replacement := accept()
	if fresh.id != old.id || fresh.session == old.session {
		t.Fatal("expected overlapping IDs on distinct connections")
	}

	send := func(peer *quic.Conn, p *packetConn, payload byte) {
		t.Helper()
		out, err := peer.OpenUniStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		frame := binary.BigEndian.AppendUint16([]byte{version, 2}, p.id)
		frame = append(frame, 0, 1, 1, 0, 0, 1)
		addr, err := addressBytes("192.0.2.1:53")
		if err != nil {
			t.Fatal(err)
		}
		frame = append(frame, addr...)
		if _, err := out.Write(append(frame, payload)); err != nil {
			t.Fatal(err)
		}
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
	}
	send(original, old, 'a')
	send(replacement, fresh, 'b')
	for p, want := range map[*packetConn]byte{old: 'a', fresh: 'b'} {
		var got [1]byte
		_ = p.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, _, err := p.ReadFrom(got[:]); err != nil || n != 1 || got[0] != want {
			t.Fatalf("UDP response %q, %v; want %c", got, err, want)
		}
	}
	if _, err := serverTCP.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	_ = tcp.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(tcp, reply[:]); err != nil || string(reply[:]) != "ok" {
		t.Fatalf("TCP response %q, %v", reply, err)
	}
	_ = old.Close()
	if _, err := io.Copy(io.Discard, auth); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint16{last.id, old.id} {
		stream, err := original.AcceptUniStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var frame [4]byte
		if _, err := io.ReadFull(stream, frame[:]); err != nil || !bytes.Equal(frame[:], binary.BigEndian.AppendUint16([]byte{version, 3}, id)) {
			t.Fatalf("Dissociate %x, %v; want ID %d", frame, err, id)
		}
	}
	_ = tcp.Close()
	select {
	case <-original.Context().Done():
	case <-ctx.Done():
		t.Fatal("original connection did not drain")
	}
	if replacement.Context().Err() != nil {
		t.Fatal("draining original connection closed replacement")
	}
}
