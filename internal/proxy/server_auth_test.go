package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"bimeron/internal/routing"
	"bimeron/internal/socksauth"
	"golang.getoutline.org/sdk/transport"
)

func echoListener(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

var unusedProxy = transport.FuncStreamDialer(func(context.Context, string) (transport.StreamConn, error) {
	return nil, io.ErrUnexpectedEOF
})

func authServer(t *testing.T) string {
	t.Helper()
	p, err := routing.Compile(routing.Config{Default: routing.Direct})
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := start(t, &Server{Proxy: unusedProxy, Policy: p, Auth: socksauth.New("alice", "s3cret")})
	return address
}

func dialSOCKS(t *testing.T, address string, greeting []byte) (net.Conn, []byte) {
	t.Helper()
	c, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(greeting); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal(err)
	}
	return c, reply[:]
}

func TestListenerAuthentication(t *testing.T) {
	address := authServer(t)
	port := echoListener(t)
	auth := func(user, pass string) []byte {
		b := append([]byte{1, byte(len(user))}, user...)
		return append(append(b, byte(len(pass))), pass...)
	}

	c, reply := dialSOCKS(t, address, []byte{5, 2, 0, 2})
	if !bytes.Equal(reply, []byte{5, 2}) {
		t.Fatalf("method selection: %x", reply)
	}
	_, _ = c.Write(auth("alice", "s3cret"))
	var status [2]byte
	if _, err := io.ReadFull(c, status[:]); err != nil || status != [2]byte{1, 0} {
		t.Fatalf("authentication: %x %v", status, err)
	}
	_, _ = c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
	var response [10]byte
	if _, err := io.ReadFull(c, response[:]); err != nil || response[1] != 0 {
		t.Fatalf("CONNECT after authentication: %x %v", response, err)
	}
	_, _ = c.Write([]byte("ping"))
	var payload [4]byte
	if _, err := io.ReadFull(c, payload[:]); err != nil || string(payload[:]) != "ping" {
		t.Fatalf("relay after authentication: %v", err)
	}

	c, reply = dialSOCKS(t, address, []byte{5, 1, 2})
	if !bytes.Equal(reply, []byte{5, 2}) {
		t.Fatalf("method selection: %x", reply)
	}
	_, _ = c.Write(auth("alice", "wrong"))
	if rest, err := io.ReadAll(c); err != nil || !bytes.Equal(rest, []byte{1, 1}) {
		t.Fatalf("wrong password reply: %x, %v", rest, err)
	}

	c, reply = dialSOCKS(t, address, []byte{5, 1, 0})
	if !bytes.Equal(reply, []byte{5, 0xff}) {
		t.Fatalf("anonymous client was not refused: %x", reply)
	}
	if rest, err := io.ReadAll(c); err != nil || len(rest) != 0 {
		t.Fatalf("after refusal: %x, %v", rest, err)
	}
}

func TestUDPAssociateRequiresAuthentication(t *testing.T) {
	address, _, _ := start(t, &Server{Proxy: unusedProxy, Packet: &resolvedPackets{}, Auth: socksauth.New("alice", "s3cret")})
	request := []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, tc := range []struct {
		password string
		status   byte
	}{{"wrong", 1}, {"s3cret", 0}} {
		t.Run(tc.password, func(t *testing.T) {
			c, method := dialSOCKS(t, address, []byte{5, 1, 2})
			if !bytes.Equal(method, []byte{5, 2}) {
				t.Fatalf("method selection: %x", method)
			}
			auth := append([]byte{1, 5}, "alice"...)
			auth = append(append(auth, byte(len(tc.password))), tc.password...)
			if _, err := c.Write(auth); err != nil {
				t.Fatal(err)
			}
			var status [2]byte
			if _, err := io.ReadFull(c, status[:]); err != nil || status != [2]byte{1, tc.status} {
				t.Fatalf("authentication: %x, %v", status, err)
			}
			if tc.status != 0 {
				if rest, err := io.ReadAll(c); err != nil || len(rest) != 0 {
					t.Fatalf("UDP ASSOCIATE after denial: %x, %v", rest, err)
				}
				return
			}
			var reply [10]byte
			if _, err := c.Write(request); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(c, reply[:]); err != nil || !bytes.Equal(reply[:4], []byte{5, 0, 0, 1}) || (reply[8] == 0 && reply[9] == 0) {
				t.Fatalf("UDP ASSOCIATE: %x, %v", reply, err)
			}
		})
	}
}

func TestListenerWithoutAuthenticationRefusesPasswordOnlyClients(t *testing.T) {
	p, err := routing.Compile(routing.Config{Default: routing.Direct})
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := start(t, &Server{Proxy: unusedProxy, Policy: p})
	if _, reply := dialSOCKS(t, address, []byte{5, 1, 2}); !bytes.Equal(reply, []byte{5, 0xff}) {
		t.Fatalf("reply: %x", reply)
	}
}
