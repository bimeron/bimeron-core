package vpn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

type checkStreamConn struct{ net.Conn }

func (c checkStreamConn) CloseRead() error  { return c.Close() }
func (c checkStreamConn) CloseWrite() error { return c.Close() }

type checkStreamDialer func(context.Context, string) (transport.StreamConn, error)

func (f checkStreamDialer) DialStream(ctx context.Context, address string) (transport.StreamConn, error) {
	return f(ctx, address)
}

func TestCheckDNSFallsBackToTCP(t *testing.T) {
	udp := packetListenerFunc(func(context.Context) (net.PacketConn, error) { return nil, errors.New("UDP unavailable") })
	tcp := checkStreamDialer(func(context.Context, string) (transport.StreamConn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var size [2]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(server, query); err != nil {
				return
			}
			answer := dnsAnswer(query, dnsmessage.RCodeSuccess)
			binary.BigEndian.PutUint16(size[:], uint16(len(answer)))
			_, _ = server.Write(append(size[:], answer...))
		}()
		return checkStreamConn{client}, nil
	})
	if err := checkDNS(context.Background(), tcp, udp, []string{"203.0.113.1"}); err != nil {
		t.Fatal(err)
	}
}

func TestCheckDNSWithoutUDP(t *testing.T) {
	tcp := checkStreamDialer(func(context.Context, string) (transport.StreamConn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var size [2]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(server, query); err != nil {
				return
			}
			answer := dnsAnswer(query, dnsmessage.RCodeSuccess)
			binary.BigEndian.PutUint16(size[:], uint16(len(answer)))
			_, _ = server.Write(append(size[:], answer...))
		}()
		return checkStreamConn{client}, nil
	})
	if err := checkDNS(t.Context(), tcp, nil, []string{"203.0.113.1"}); err != nil {
		t.Fatal(err)
	}
}
