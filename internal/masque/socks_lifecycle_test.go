package masque

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/masque/masquetest"
	"bimeron/internal/proxy"
)

type observedPackets struct {
	client     *Client
	failures   chan error
	templateMu *sync.Mutex
}

func (o observedPackets) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	packet, err := o.client.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	return &observedPacket{PacketConn: packet, failures: o.failures, templateMu: o.templateMu}, nil
}

type observedPacket struct {
	net.PacketConn
	failures   chan error
	templateMu *sync.Mutex
}

func (p *observedPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.templateMu.Lock()
	defer p.templateMu.Unlock()
	return p.PacketConn.WriteTo(b, addr)
}

func (p *observedPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, from, err := p.PacketConn.ReadFrom(b)
	if err != nil {
		select {
		case p.failures <- err:
		default:
		}
	}
	return n, from, err
}

func TestSOCKSAssociationSurvivesDestinationFailure(t *testing.T) {
	endpoints := masquetest.Start(t)
	client := fixtureClient(t, endpoints)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	failures := make(chan error, 4)
	var templateMu sync.Mutex
	setPath := func(path string) {
		templateMu.Lock()
		defer templateMu.Unlock()
		client.template = mustTemplate(t, client.authority, path)
	}
	go func() {
		done <- (&proxy.Server{Proxy: client, Packet: observedPackets{client: client, failures: failures, templateMu: &templateMu}}).Serve(ctx, listener)
	}()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("SOCKS association prevented shutdown")
		}
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	socks := &proxy.SOCKS5{Endpoint: accesskey.Endpoint{Host: host, Port: port}}
	packet, err := socks.ListenPacket(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	echo(t, packet, endpoints["udp"], []byte("healthy-first-target"))
	setPath("/malformed_capsule/")
	if _, err := packet.WriteTo([]byte("trigger"), packetAddr(endpoints["udp2"])); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-failures:
		var operation *net.OpError
		if !errors.As(err, &operation) || operation.Addr == nil || operation.Addr.String() != endpoints["udp2"] || !operation.Temporary() {
			t.Fatalf("expected destination-scoped retryable failure, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("failed destination did not report its tunnel error")
	}
	// The relay consumes the transient error; the TCP control connection and the
	// healthy target must remain usable without a new UDP ASSOCIATE request.
	echo(t, packet, endpoints["udp"], []byte("healthy-target-survives"))
	setPath("/.well-known/masque/udp/")
	echo(t, packet, endpoints["udp2"], []byte("failed-target-reopens"))
}
