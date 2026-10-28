package masque

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func lifecycleTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	fixture := httptest.NewTLSServer(nil)
	t.Cleanup(fixture.Close)
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	return &tls.Config{Certificates: fixture.TLS.Certificates, NextProtos: []string{"h3"}}, roots
}
func lifecycleClient(t *testing.T, endpoint string, roots *x509.CertPool) *Client {
	t.Helper()
	profile, err := accesskey.ParseMASQUE("masque://" + endpoint)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(profile, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	client.roots = roots
	t.Cleanup(func() { _ = client.Close() })
	return client
}
func lifecycleServer(t *testing.T, handler http.Handler) (*Client, *http3.Server) {
	t.Helper()
	tlsConf, roots := lifecycleTLS(t)
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: tlsConf, EnableDatagrams: true, QUICConfig: &quic.Config{InitialStreamReceiveWindow: 4096, MaxStreamReceiveWindow: 4096}, Handler: handler}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(socket) }()
	t.Cleanup(func() { _ = server.Close(); _ = socket.Close(); <-done })
	return lifecycleClient(t, socket.LocalAddr().String(), roots), server
}

func TestTCPWriteThenClosePreservesPayload(t *testing.T) {
	for _, goAway := range []bool{false, true} {
		name := "active"
		if goAway {
			name = "after_GOAWAY"
		}
		t.Run(name, func(t *testing.T) {
			closed := make(chan struct{})
			type received struct {
				data []byte
				err  error
			}
			result := make(chan received, 1)
			client, server := lifecycleServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				stream := w.(http3.HTTPStreamer).HTTPStream()
				defer stream.Close()
				select {
				case <-closed:
				case <-r.Context().Done():
					return
				}
				data, err := io.ReadAll(stream)
				result <- received{data, err}
			}))
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			stream, err := client.DialStream(ctx, "127.0.0.1:1234")
			if err != nil {
				t.Fatal(err)
			}
			shutdown := make(chan error, 1)
			if goAway {
				oldConn := client.conn
				go func() { shutdown <- server.Shutdown(ctx) }()
				waitUntil(t, func() bool {
					probe, err := oldConn.OpenRequestStream(ctx)
					if err == nil {
						probe.CancelRead(0)
						probe.CancelWrite(0)
						return false
					}
					if !strings.Contains(err.Error(), "graceful shutdown") {
						t.Fatalf("waiting for GOAWAY: %v", err)
					}
					return true
				})
			}
			payload := []byte("completed write must survive Close")
			if n, err := stream.Write(payload); err != nil || n != len(payload) {
				t.Fatal(n, err)
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			close(closed)
			select {
			case got := <-result:
				if got.err != nil || !bytes.Equal(got.data, payload) {
					t.Fatalf("received %q: %v", got.data, got.err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			waitUntil(t, func() bool { return len(client.slots) == 0 })
			if goAway {
				select {
				case err := <-shutdown:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
		})
	}
}

// Receiving EOF (or closing reads) must not discard later writes during GOAWAY.
func TestTCPWriteAfterReceiveCloseAndGoAway(t *testing.T) {
	for _, receive := range []string{"EOF", "CloseRead"} {
		for _, finish := range []string{"Close", "CloseWrite"} {
			t.Run(receive+"/"+finish, func(t *testing.T) {
				t.Parallel()
				gate := make(chan struct{})
				type received struct {
					data []byte
					err  error
				}
				result := make(chan received, 1)
				client, server := lifecycleServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(200)
					stream := w.(http3.HTTPStreamer).HTTPStream()
					defer stream.Close()
					if receive == "EOF" {
						_ = stream.Close()
					}
					select {
					case <-gate:
					case <-t.Context().Done():
						return
					}
					data, err := io.ReadAll(stream)
					result <- received{data, err}
				}))
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				stream, err := client.DialStream(ctx, "127.0.0.1:1234")
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
				if receive == "EOF" {
					if data, err := io.ReadAll(stream); err != nil || len(data) != 0 {
						t.Fatalf("EOF: %q %v", data, err)
					}
				} else if err := stream.CloseRead(); err != nil {
					t.Fatal(err)
				}
				oldConn := client.conn
				shutdown := make(chan error, 1)
				go func() { shutdown <- server.Shutdown(ctx) }()
				waitUntil(t, func() bool {
					probe, err := oldConn.OpenRequestStream(ctx)
					if err == nil {
						probe.CancelRead(0)
						probe.CancelWrite(0)
						return false
					}
					if !strings.Contains(err.Error(), "graceful shutdown") {
						t.Fatalf("waiting for GOAWAY: %v", err)
					}
					return true
				})
				payload := []byte("final bytes after receive completion")
				if n, err := stream.Write(payload); err != nil || n != len(payload) {
					t.Fatal(n, err)
				}
				if finish == "CloseWrite" {
					err = stream.CloseWrite()
				} else {
					err = stream.Close()
				}
				if err != nil {
					t.Fatal(err)
				}
				if finish == "CloseWrite" {
					if n, err := stream.Write([]byte("too late")); n != 0 || err == nil {
						t.Fatalf("Write after CloseWrite: %d %v", n, err)
					}
				}
				waitUntil(t, func() bool { return stream.(*streamConn).SendCompletionContext().Err() != nil })
				close(gate)
				select {
				case got := <-result:
					if got.err != nil || !bytes.Equal(got.data, payload) {
						t.Fatalf("received %q: %v", got.data, got.err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				select {
				case err := <-shutdown:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			})
		}
	}
}

func TestTCPCloseInterruptsBlockedWrite(t *testing.T) {
	client, _ := lifecycleServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		stream := w.(http3.HTTPStreamer).HTTPStream()
		// Do not consume payload or increase the stream receive window.
		<-stream.Context().Done()
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	raw, err := client.DialStream(ctx, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	stream := raw.(*streamConn)
	_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	written := make(chan error, 1)
	go func() { _, err := stream.Write(make([]byte, 1024*1024)); written <- err }()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for stream.writeMu.TryLock() {
		stream.writeMu.Unlock()
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- stream.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked on a flow-controlled write")
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("blocked write unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt Write")
	}
}

func TestTCPCloseInterruptsReadAndBoundsSendCompletion(t *testing.T) {
	for _, cleanup := range []string{"ACK", "timeout", "client_close"} {
		t.Run(cleanup, func(t *testing.T) {
			peerFIN := make(chan struct{})
			client, _ := lifecycleServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				stream := w.(http3.HTTPStreamer).HTTPStream()
				defer stream.Close()
				select {
				case <-peerFIN:
				case <-r.Context().Done():
				}
			}))
			paused := pauseClientPackets(t, client)
			raw, err := client.DialStream(t.Context(), "127.0.0.1:1234")
			if err != nil {
				t.Fatal(err)
			}
			stream := raw.(*streamConn)
			read := make(chan error, 8)
			go func() { _, err := stream.Read(make([]byte, 1)); read <- err }()
			waitUntil(t, func() bool {
				return len(stream.readMu) == 1
			})
			for range 7 {
				go func() { _, err := stream.Read(make([]byte, 1)); read <- err }()
			}
			paused.Store(true)
			started := time.Now()
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			for range 8 {
				select {
				case err := <-read:
					if !errors.Is(err, net.ErrClosed) {
						t.Fatalf("Read after Close: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("Close did not interrupt Read")
				}
			}
			for _, set := range []func(time.Time) error{stream.SetDeadline, stream.SetReadDeadline, stream.SetWriteDeadline} {
				if err := set(time.Time{}); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("deadline after Close: %v", err)
				}
			}
			if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("new Read after Close: %v", err)
			}
			if _, err := stream.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Write after Close: %v", err)
			}
			if err := stream.CloseRead(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("CloseRead after Close: %v", err)
			}
			if len(client.slots) != 1 {
				t.Fatal("unacknowledged send released its tunnel slot early")
			}
			switch cleanup {
			case "ACK":
				paused.Store(false)
				close(peerFIN)
			case "client_close":
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			}
			// Include scheduling margin beyond the production send-completion deadline.
			deadline := time.After(closeSendTimeout + 2*time.Second)
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for len(client.slots) != 0 {
				select {
				case <-ticker.C:
				case <-deadline:
					t.Fatal("send completion did not release its tunnel slot")
				}
			}
			if cleanup == "timeout" && time.Since(started) < closeSendTimeout {
				t.Fatal("send completed before its deadline without ACK")
			}
		})
	}
}

// pauseClientPackets can drop outbound QUIC packets after the handshake, so
// completion cleanup is tested independently of peer application reads.
func pauseClientPackets(t *testing.T, client *Client) *atomic.Bool {
	t.Helper()
	target, err := net.ResolveUDPAddr("udp", net.JoinHostPort(client.profile.TCP.Host, strconv.Itoa(client.profile.TCP.Port)))
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client.profile.TCP.Port = socket.LocalAddr().(*net.UDPAddr).Port
	paused := &atomic.Bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var peer net.Addr
		b := make([]byte, 65535)
		for {
			n, from, err := socket.ReadFrom(b)
			if err != nil {
				return
			}
			if from.String() == target.String() {
				if peer != nil {
					_, _ = socket.WriteTo(b[:n], peer)
				}
			} else {
				peer = from
				if !paused.Load() {
					_, _ = socket.WriteTo(b[:n], target)
				}
			}
		}
	}()
	t.Cleanup(func() { _ = socket.Close(); <-done })
	return paused
}

type drainingPeer struct {
	server *http3.Server
	conn   *quic.Conn
}

func drainingProxy(t *testing.T) (*Client, <-chan drainingPeer) {
	t.Helper()
	tlsConf, roots := lifecycleTLS(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan drainingPeer, 8)
	ctx, cancel := context.WithCancel(t.Context())
	acceptDone := make(chan struct{})
	var servers []*http3.Server
	var workers sync.WaitGroup
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			server := &http3.Server{EnableDatagrams: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Proto == "connect-udp" {
					w.Header().Set(http3.CapsuleProtocolHeader, "?1")
				}
				w.WriteHeader(200)
				stream := w.(http3.HTTPStreamer).HTTPStream()
				if r.Proto != "connect-udp" {
					defer stream.CancelRead(0)
					defer stream.Close()
					_, _ = io.Copy(stream, stream)
					return
				}
				owned, stop := context.WithCancel(r.Context())
				defer stop()
				readDone := make(chan struct{})
				go func() {
					defer close(readDone)
					_, _ = io.Copy(io.Discard, stream)
					stream.CancelRead(0)
					stream.CancelWrite(0)
					stop()
				}()
				defer func() { stream.CancelRead(0); stream.CancelWrite(0); <-readDone }()
				for {
					data, err := stream.ReceiveDatagram(owned)
					if err != nil {
						return
					}
					if err := stream.SendDatagram(data); err != nil {
						return
					}
				}
			})}
			servers = append(servers, server)
			workers.Add(1)
			go func() { defer workers.Done(); _ = server.ServeQUICConn(conn) }()
			select {
			case accepted <- drainingPeer{server, conn}:
			case <-ctx.Done():
				return
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-acceptDone
		for _, server := range servers {
			_ = server.Close()
		}
		workers.Wait()
	})
	return lifecycleClient(t, listener.Addr().String(), roots), accepted
}
func waitUntil(t *testing.T, ready func() bool) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !ready() {
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("condition did not become ready")
		}
	}
}
func streamEcho(t *testing.T, stream io.ReadWriter, payload string) {
	t.Helper()
	if _, err := io.WriteString(stream, payload); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, b); err != nil || string(b) != payload {
		t.Fatalf("echo %q: %v", b, err)
	}
}

func TestGoAwayReplacesConnectionWithoutAbortingTunnels(t *testing.T) {
	client, accepted := drainingProxy(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	oldTCP, err := client.DialStream(ctx, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	defer oldTCP.Close()
	_ = oldTCP.SetDeadline(time.Now().Add(10 * time.Second))
	oldUDP, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer oldUDP.Close()
	echo(t, oldUDP, "127.0.0.1:1234", []byte("old-udp"))
	client.mu.Lock()
	oldConn := client.conn
	generation := client.generations[oldConn]
	client.mu.Unlock()
	first := <-accepted
	shutdown := make(chan error, 1)
	go func() { shutdown <- first.server.Shutdown(ctx) }()
	// Probe only stream creation to observe that the client's GOAWAY reader has
	// run. No CONNECT request or application bytes are sent by these probes.
	waitUntil(t, func() bool {
		stream, err := oldConn.OpenRequestStream(ctx)
		if err == nil {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			return false
		}
		if !strings.Contains(err.Error(), "graceful shutdown") {
			t.Fatalf("waiting for GOAWAY: %v", err)
		}
		return true
	})
	newTCP, err := client.DialStream(ctx, "127.0.0.1:1235")
	if err != nil {
		t.Fatal(err)
	}
	defer newTCP.Close()
	_ = newTCP.SetDeadline(time.Now().Add(10 * time.Second))
	second := <-accepted
	if second.conn == first.conn {
		t.Fatal("GOAWAY connection reused")
	}
	streamEcho(t, newTCP, "new-tcp")
	streamEcho(t, oldTCP, "old-tcp-survives")
	echo(t, oldUDP, "127.0.0.1:1234", []byte("old-udp-survives"))
	// A new destination on the same packet listener must use the new generation.
	echo(t, oldUDP, "127.0.0.1:1235", []byte("new-udp"))
	client.mu.Lock()
	count := len(client.generations)
	client.mu.Unlock()
	if count != 2 {
		t.Fatalf("expected active and draining generations, got %d", count)
	}
	_ = oldTCP.Close()
	_ = oldUDP.Close()
	select {
	case <-first.conn.Context().Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waitUntil(t, func() bool { client.mu.Lock(); defer client.mu.Unlock(); return len(client.generations) == 1 })
	if err := generation.socket.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("retired socket not closed: %v", err)
	}
	streamEcho(t, newTCP, "new-connection-still-works")
	select {
	case err := <-shutdown:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-second.conn.Context().Done():
	case <-ctx.Done():
		t.Fatal("Close did not release the new generation")
	}
}

func TestConcurrentGoAwayReplacementAndClientClose(t *testing.T) {
	client, accepted := drainingProxy(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	old, err := client.DialStream(ctx, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	first := <-accepted
	client.mu.Lock()
	oldConn := client.conn
	client.mu.Unlock()
	shutdown := make(chan error, 1)
	go func() { shutdown <- first.server.Shutdown(ctx) }()
	waitUntil(t, func() bool {
		probe, err := oldConn.OpenRequestStream(ctx)
		if err == nil {
			probe.CancelRead(0)
			probe.CancelWrite(0)
			return false
		}
		return strings.Contains(err.Error(), "graceful shutdown")
	})
	const writers = 8
	results := make(chan error, writers)
	for range writers {
		go func() {
			stream, err := client.DialStream(ctx, "127.0.0.1:1235")
			if err != nil {
				results <- err
				return
			}
			defer stream.Close()
			_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := stream.Write([]byte("new")); err != nil {
				results <- err
				return
			}
			b := make([]byte, 3)
			_, err = io.ReadFull(stream, b)
			if err == nil && string(b) != "new" {
				err = io.ErrUnexpectedEOF
			}
			results <- err
		}()
	}
	for range writers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	second := <-accepted
	select {
	case <-accepted:
		t.Fatal("concurrent requests created extra replacement connections")
	default:
	}
	streamEcho(t, old, "old-survives-concurrent-replacement")
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []drainingPeer{first, second} {
		select {
		case <-peer.conn.Context().Done():
		case <-ctx.Done():
			t.Fatal("Close did not release every generation")
		}
	}
	waitUntil(t, func() bool { client.mu.Lock(); defer client.mu.Unlock(); return len(client.generations) == 0 })
	select {
	case err := <-shutdown:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
