package trojan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

func TestTrojanTCPAndUDPOverTLS(t *testing.T) {
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := fixture.TLS.Certificates[0]
	root := x509.NewCertPool()
	root.AddCert(fixture.Certificate())
	fixture.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErrors := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			connection, err := listener.Accept()
			if err != nil {
				serverErrors <- err
				return
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
			var password [58]byte
			if _, err := io.ReadFull(connection, password[:]); err != nil {
				serverErrors <- err
				return
			}
			hash := sha256.Sum224([]byte("secret"))
			if string(password[:56]) != hex.EncodeToString(hash[:]) || string(password[56:]) != "\r\n" {
				serverErrors <- io.ErrUnexpectedEOF
				return
			}
			var command [1]byte
			if _, err := io.ReadFull(connection, command[:]); err != nil {
				serverErrors <- err
				return
			}
			target, err := readAddress(connection)
			if err != nil {
				serverErrors <- err
				return
			}
			var end [2]byte
			if _, err := io.ReadFull(connection, end[:]); err != nil || string(end[:]) != "\r\n" {
				serverErrors <- io.ErrUnexpectedEOF
				return
			}
			if command[0] == 1 {
				if target.String() != "example.com:80" {
					serverErrors <- io.ErrUnexpectedEOF
					return
				}
				var data [4]byte
				_, err = io.ReadFull(connection, data[:])
				if err == nil && string(data[:]) == "ping" {
					_, err = connection.Write([]byte("pong"))
				}
			} else if command[0] == 3 {
				if target.String() != "0.0.0.0:0" {
					serverErrors <- io.ErrUnexpectedEOF
					return
				}
				address, readErr := readAddress(connection)
				if readErr != nil || address.String() != "1.1.1.1:53" {
					serverErrors <- io.ErrUnexpectedEOF
					return
				}
				var tail [4]byte
				_, err = io.ReadFull(connection, tail[:])
				if err == nil && binary.BigEndian.Uint16(tail[:2]) == 4 && string(tail[2:]) == "\r\n" {
					var data [4]byte
					_, err = io.ReadFull(connection, data[:])
					if err == nil && string(data[:]) == "ping" {
						frame, _ := addressBytes("1.1.1.1:53")
						frame = binary.BigEndian.AppendUint16(frame, 4)
						frame = append(frame, '\r', '\n')
						frame = append(frame, "pong"...)
						_, err = connection.Write(frame)
					}
				}
			} else {
				err = io.ErrUnexpectedEOF
			}
			serverErrors <- err
		}()
	}
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	profile := accesskey.Profile{Type: "trojan", TCP: accesskey.Endpoint{Host: host, Port: port}, Trojan: accesskey.Trojan{Password: "secret", ServerName: "127.0.0.1"}}
	client, err := New(profile, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	client.rootCAs = root
	defer client.Close()
	stream, err := client.DialStream(context.Background(), "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var answer [4]byte
	if _, err := io.ReadFull(stream, answer[:]); err != nil || string(answer[:]) != "pong" {
		t.Fatalf("TCP reply %q: %v", answer, err)
	}
	_ = stream.Close()
	packet, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	if _, err := packet.WriteTo([]byte("ping"), trojanAddr("1.1.1.1:53")); err != nil {
		t.Fatal(err)
	}
	_ = packet.SetReadDeadline(time.Now().Add(5 * time.Second))
	var udp [4]byte
	n, from, err := packet.ReadFrom(udp[:])
	if err != nil || n != 4 || !bytes.Equal(udp[:], []byte("pong")) || from.String() != "1.1.1.1:53" {
		t.Fatalf("UDP reply %q from %v: %v", udp, from, err)
	}
	for i := 0; i < 2; i++ {
		if err := <-serverErrors; err != nil {
			t.Fatal(err)
		}
	}
}

func TestTrojanRejectsUntrustedTLS(t *testing.T) {
	for _, network := range []string{"tcp", "ws", "grpc"} {
		t.Run(network, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
			port, _ := strconv.Atoi(portText)
			settings := accesskey.Trojan{Password: "secret", ServerName: "127.0.0.1", Network: network}
			if network == "grpc" {
				settings.GRPCServiceName = "trojan"
			}
			client, err := New(accesskey.Profile{Type: "trojan", TCP: accesskey.Endpoint{Host: host, Port: port}, Trojan: settings}, net.Dialer{})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			if connection, err := client.DialStream(ctx, "example.com:80"); err == nil {
				_ = connection.Close()
				t.Fatal("untrusted certificate accepted")
			}
		})
	}
}

func TestTrojanWebSocketHandshakeCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer server.Close()
	host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	client, err := New(accesskey.Profile{Type: "trojan", TCP: accesskey.Endpoint{Host: host, Port: port}, Trojan: accesskey.Trojan{Password: "secret", ServerName: "127.0.0.1", Network: "ws"}}, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.rootCAs = x509.NewCertPool()
	client.rootCAs.AddCert(server.Certificate())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := client.DialStream(ctx, "example.com:80")
		if err == nil {
			c.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("handshake did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt handshake")
	}
}
