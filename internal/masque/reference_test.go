package masque

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"bimeron/internal/masque/masquetest"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/dns/dnsmessage"
)

func fixtureClient(t testing.TB, endpoints map[string]string) *Client {
	t.Helper()
	c, err := New(masquetest.Profile(t, endpoints), net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func echo(t testing.TB, p net.PacketConn, target string, data []byte) {
	t.Helper()
	_ = p.SetDeadline(time.Now().Add(5 * time.Second))
	n, err := p.WriteTo(data, packetAddr(target))
	if err != nil || n != len(data) {
		t.Fatalf("UDP write: %d %v", n, err)
	}
	b := make([]byte, maxPayload)
	n, from, err := p.ReadFrom(b)
	if err != nil || from == nil || from.String() != target || !bytes.Equal(b[:n], data) {
		t.Fatalf("UDP echo from %v: %q %v", from, b[:n], err)
	}
}

func TestReferenceServer(t *testing.T) {
	endpoints := masquetest.Start(t)
	t.Run("tcp_half_close_and_dial_context", func(t *testing.T) {
		c := fixtureClient(t, endpoints)
		ctx, cancel := context.WithCancel(t.Context())
		stream, err := c.DialStream(ctx, endpoints["tcp"])
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		data := bytes.Repeat([]byte("tcp"), 8192)
		if _, err := stream.Write(data); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, len(data))
		if _, err := io.ReadFull(stream, b); err != nil || !bytes.Equal(b, data) {
			t.Fatalf("TCP echo: %v", err)
		}
		if err := stream.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(stream); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("udp_destinations_empty_ipv6_and_isolation", func(t *testing.T) {
		c := fixtureClient(t, endpoints)
		var bindings atomic.Int32
		c.dialer.Control = func(network, address string, raw syscall.RawConn) error {
			if !strings.HasPrefix(network, "udp") {
				return fmt.Errorf("unexpected socket network")
			}
			bindings.Add(1)
			return nil
		}
		packet, err := c.ListenPacket(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer packet.Close()
		other, err := c.ListenPacket(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		for _, target := range []string{endpoints["udp"], endpoints["udp2"], endpoints["udp6"]} {
			if target == "" {
				continue
			}
			echo(t, packet, target, []byte("datagram"))
			echo(t, packet, target, nil)
		}
		_ = packet.Close()
		echo(t, other, endpoints["udp"], []byte("still-open"))
		if bindings.Load() != 1 {
			t.Fatalf("expected one bound shared QUIC socket, got %d", bindings.Load())
		}
	})
	t.Run("dns", func(t *testing.T) {
		c := fixtureClient(t, endpoints)
		packet, err := c.ListenPacket(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer packet.Close()
		name, _ := dnsmessage.NewName("example.test.")
		query := dnsmessage.Message{Header: dnsmessage.Header{ID: 123, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		b, err := query.Pack()
		if err != nil {
			t.Fatal(err)
		}
		_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := packet.WriteTo(b, packetAddr(endpoints["dns"])); err != nil {
			t.Fatal(err)
		}
		b = make([]byte, 1500)
		n, _, err := packet.ReadFrom(b)
		var answer dnsmessage.Message
		if err != nil || answer.Unpack(b[:n]) != nil || !answer.Response || answer.ID != 123 || len(answer.Answers) != 1 {
			t.Fatalf("DNS answer: %v", err)
		}
	})
	for _, path := range []string{"server", "loss_server"} {
		t.Run("nested_http3_"+path, func(t *testing.T) {
			fixture := make(map[string]string)
			for key, value := range endpoints {
				fixture[key] = value
			}
			fixture["server"] = endpoints[path]
			c := fixtureClient(t, fixture)
			packet, err := c.ListenPacket(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			qt := &quic.Transport{Conn: packet}
			defer qt.Close()
			remote, err := net.ResolveUDPAddr("udp", endpoints["http3"])
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			conn, err := qt.Dial(ctx, remote, &tls.Config{ServerName: "localhost", RootCAs: c.roots, NextProtos: []string{"h3"}}, &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseWithError(0, "")
			h3 := &http3.Transport{}
			req, err := http.NewRequestWithContext(ctx, "GET", "https://localhost/", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := h3.NewClientConn(conn).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			b, err := io.ReadAll(response.Body)
			if err != nil || string(b) != "http3-through-masque" {
				t.Fatalf("HTTP/3 response: %q %v", b, err)
			}
		})
	}
	t.Run("failures", func(t *testing.T) {
		for _, name := range []string{"untrusted_ca", "wrong_name", "authentication", "no_datagrams", "no_extended_connect", "bad_capsule", "oversized_header", "rejected", "wrong_path"} {
			t.Run(name, func(t *testing.T) {
				c := fixtureClient(t, endpoints)
				switch name {
				case "untrusted_ca":
					c.roots = x509.NewCertPool()
				case "wrong_name":
					c.profile.MASQUE.ServerName = "wrong.invalid"
				case "authentication":
					c.profile.TCP.Secret = "synthetic-secret"
				case "no_datagrams", "no_extended_connect":
					_, port, _ := net.SplitHostPort(endpoints[name])
					c.profile.TCP.Port, _ = strconv.Atoi(port)
				case "bad_capsule", "oversized_header":
					c.template = mustTemplate(t, c.authority, "/"+name+"/")
				case "rejected":
					c.template = mustTemplate(t, c.authority, "/reject/")
				case "wrong_path":
					c.template = mustTemplate(t, c.authority, "/unsupported/")
				}
				packet, err := c.ListenPacket(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				_ = packet.SetWriteDeadline(time.Now().Add(5 * time.Second))
				n, err := packet.WriteTo([]byte("failure"), packetAddr(endpoints["udp"]))
				if err == nil || n != 0 || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(err.Error(), "fixture-pass") {
					t.Fatalf("expected sanitized failure, got %d %v", n, err)
				}
			})
		}
	})
	t.Run("custom_template_and_extensions", func(t *testing.T) {
		c := fixtureClient(t, endpoints)
		c.template = mustTemplate(t, c.authority, "/custom/")
		packet, err := c.ListenPacket(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer packet.Close()
		echo(t, packet, endpoints["udp"], []byte("custom"))
		c.template = mustTemplate(t, c.authority, "/inject/")
		_, port, _ := net.SplitHostPort(endpoints["udp2"])
		echo(t, packet, net.JoinHostPort("localhost", port), []byte("ignore-extensions"))
	})
	t.Run("malformed_capsule_and_short_buffer", func(t *testing.T) {
		c := fixtureClient(t, endpoints)
		c.template = mustTemplate(t, c.authority, "/malformed_capsule/")
		p, err := c.ListenPacket(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		_ = p.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := p.WriteTo([]byte("trigger"), packetAddr(endpoints["udp"])); err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.ReadFrom(make([]byte, 32)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("malformed capsule not terminated: %v", err)
		}
		c.template = mustTemplate(t, c.authority, "/.well-known/masque/udp/")
		if _, err := p.WriteTo([]byte("long datagram"), packetAddr(endpoints["udp2"])); err != nil {
			t.Fatal(err)
		}
		if n, _, err := p.ReadFrom(make([]byte, 1)); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
			t.Fatalf("packet boundary: %d %v", n, err)
		}
		echo(t, p, endpoints["udp2"], []byte("next-packet"))
	})
	t.Run("deadline_reset_cancellation_and_limits", func(t *testing.T) {
		c := fixtureClient(t, endpoints)
		ctx, cancel := context.WithCancel(t.Context())
		packet, err := c.ListenPacket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer packet.Close()
		p := packet.(*packetConn)
		_ = p.SetReadDeadline(time.Now().Add(-time.Second))
		if _, _, err := p.ReadFrom(make([]byte, 32)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
		_ = p.SetDeadline(time.Time{})
		echo(t, p, endpoints["udp"], []byte("reset"))
		_ = p.SetWriteDeadline(time.Now().Add(-time.Second))
		if n, err := p.WriteTo([]byte("x"), packetAddr(endpoints["udp"])); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("write deadline: %d %v", n, err)
		}
		_ = p.SetDeadline(time.Time{})
		if n, err := p.WriteTo(make([]byte, maxPayload+1), packetAddr(endpoints["udp"])); n != 0 || err == nil {
			t.Fatal("oversized datagram accepted")
		}
		if n, err := p.WriteTo(make([]byte, maxPayload), packetAddr(endpoints["udp"])); n != 0 || err == nil {
			t.Fatal("QUIC datagram size error not propagated")
		}
		p.expire(time.Now().Add(2 * idleTimeout))
		echo(t, p, endpoints["udp"], []byte("reopened"))
		c.mu.Lock()
		qconn := c.generations[c.conn].quicConn
		c.mu.Unlock()
		_ = qconn.CloseWithError(0, "test reconnect")
		other, err := c.ListenPacket(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		echo(t, other, endpoints["udp"], []byte("new-generation"))
		cancel()
		if _, _, err := p.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	})
	t.Run("blocked_handshake_deadline_preserves_other_tunnels", func(t *testing.T) {
		c := fixtureClient(t, endpoints)
		stable, err := c.DialStream(t.Context(), endpoints["tcp"])
		if err != nil {
			t.Fatal(err)
		}
		defer stable.Close()
		c.template = mustTemplate(t, c.authority, "/stall/")
		packet, err := c.ListenPacket(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer packet.Close()
		_ = packet.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		started := time.Now()
		if n, err := packet.WriteTo([]byte("stall"), packetAddr(endpoints["udp"])); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(started) > time.Second {
			t.Fatalf("handshake deadline: %d %v", n, err)
		}
		_ = stable.SetDeadline(time.Now().Add(time.Second))
		if _, err := stable.Write([]byte("ok")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 2)
		if _, err := io.ReadFull(stable, b); err != nil || string(b) != "ok" {
			t.Fatal(err)
		}
	})
	t.Run("settings_timeout_and_live_write_deadline", func(t *testing.T) {
		c := fixtureClient(t, endpoints)
		_, port, _ := net.SplitHostPort(endpoints["no_settings"])
		c.profile.TCP.Port, _ = strconv.Atoi(port)
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		if _, err := c.DialStream(ctx, endpoints["tcp"]); err == nil {
			t.Fatal("peer without SETTINGS accepted")
		}
		c = fixtureClient(t, endpoints)
		c.template = mustTemplate(t, c.authority, "/stall/")
		p, err := c.ListenPacket(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		_ = p.SetWriteDeadline(time.Now().Add(time.Second))
		done := make(chan error, 1)
		go func() { _, err := p.WriteTo([]byte("blocked"), packetAddr(endpoints["udp"])); done <- err }()
		_ = p.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
		select {
		case err := <-done:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("in-flight write ignored deadline update")
		}
	})
	t.Run("concurrent_packets_and_shutdown", func(t *testing.T) {
		c := fixtureClient(t, endpoints)
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p, err := c.ListenPacket(t.Context())
				if err != nil {
					t.Error(err)
					return
				}
				defer p.Close()
				echo(t, p, endpoints["udp"], []byte("concurrent"))
			}()
		}
		wg.Wait()
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := c.ListenPacket(t.Context()); !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
		if _, err := c.DialStream(t.Context(), endpoints["tcp"]); !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	})
}

func mustTemplate(t testing.TB, authority, prefix string) *uritemplate.Template {
	t.Helper()
	template, err := uritemplate.New("https://" + authority + prefix + "{target_host}/{target_port}/")
	if err != nil {
		t.Fatal(err)
	}
	return template
}
