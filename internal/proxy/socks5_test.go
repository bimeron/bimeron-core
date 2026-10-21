package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

func TestSOCKS5ConnectAndUDP(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErrors := make(chan error, 3)
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { serverErrors <- serveSOCKSTest(c, udp.LocalAddr().(*net.UDPAddr).Port) }()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	s := &SOCKS5{Endpoint: accesskey.Endpoint{Host: "127.0.0.1", Port: port, Secret: "secret"}, Username: "alice", Dialer: net.Dialer{}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := s.DialStream(ctx, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	packet, err := s.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	_ = packet.SetDeadline(time.Now().Add(2 * time.Second))
	target := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 53}
	if _, err := packet.WriteTo([]byte("hello"), target); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, from, err := udp.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 || string(buffer[n-5:n]) != "hello" {
		t.Fatal("invalid SOCKS5 UDP frame")
	}
	if _, err := udp.WriteTo(buffer[:n], from); err != nil {
		t.Fatal(err)
	}
	n, source, err := packet.ReadFrom(buffer)
	if err != nil || n != 5 || string(buffer[:n]) != "hello" || source.String() != target.String() {
		t.Fatalf("UDP response: %s %v", source, err)
	}
	_ = packet.Close()
	for i := 0; i < 2; i++ {
		if err := <-serverErrors; err != nil {
			t.Fatal(err)
		}
	}
}

func serveSOCKSTest(c net.Conn, udpPort int) error {
	defer c.Close()
	var greeting [3]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil {
		return err
	}
	if greeting != [3]byte{5, 1, 2} {
		return io.ErrUnexpectedEOF
	}
	if _, err := c.Write([]byte{5, 2}); err != nil {
		return err
	}
	var auth [2]byte
	if _, err := io.ReadFull(c, auth[:]); err != nil {
		return err
	}
	user := make([]byte, auth[1]+1)
	if _, err := io.ReadFull(c, user); err != nil {
		return err
	}
	password := make([]byte, user[len(user)-1])
	if _, err := io.ReadFull(c, password); err != nil {
		return err
	}
	if string(user[:len(user)-1]) != "alice" || string(password) != "secret" {
		return io.ErrUnexpectedEOF
	}
	if _, err := c.Write([]byte{1, 0}); err != nil {
		return err
	}
	var request [4]byte
	if _, err := io.ReadFull(c, request[:]); err != nil {
		return err
	}
	address, err := readSocksAddress(c, request[3])
	if err != nil {
		return err
	}
	if request[1] == 1 && address != "example.com:443" {
		return io.ErrUnexpectedEOF
	}
	if request[1] == 3 && address != "0.0.0.0:0" {
		return io.ErrUnexpectedEOF
	}
	if request[1] != 1 && request[1] != 3 {
		return io.ErrUnexpectedEOF
	}
	bound := 0
	if request[1] == 3 {
		bound = udpPort
	}
	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(bound >> 8), byte(bound)}
	if _, err := c.Write(reply); err != nil {
		return err
	}
	if request[1] == 3 {
		_, _ = io.Copy(io.Discard, c)
	}
	return nil
}

func TestSOCKS5UDPAssociateRejected(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var greeting [3]byte
		_, _ = io.ReadFull(c, greeting[:])
		_, _ = c.Write([]byte{5, 0})
		var request [10]byte
		_, _ = io.ReadFull(c, request[:])
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}()
	s := &SOCKS5{Endpoint: accesskey.Endpoint{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}}
	if p, err := s.ListenPacket(context.Background()); err == nil {
		_ = p.Close()
		t.Fatal("UDP ASSOCIATE rejection accepted")
	}
}

func TestSOCKS5Address(t *testing.T) {
	for _, address := range []string{"example.com:80", "127.0.0.1:53", "[::1]:443"} {
		b, err := socksAddress(address)
		if err != nil {
			t.Fatal(err)
		}
		got, err := readSocksAddress(bytes.NewReader(b[1:]), b[0])
		if err != nil || got != address {
			t.Fatalf("%s: %s %v", address, got, err)
		}
	}
}
