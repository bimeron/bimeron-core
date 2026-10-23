package vless

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

func TestVLESSAndXUDPFrames(t *testing.T) {
	id, err := userID("123e4567-e89b-12d3-a456-426614174000")
	if err != nil {
		t.Fatal(err)
	}
	header, err := requestHeader(id, 1, "[2001:db8::1]:443", "xtls-rprx-vision")
	if err != nil || len(header) < 43 || header[0] != 0 || header[17] != 18 || header[18] != 10 || header[36] != 1 || header[39] != 3 {
		t.Fatalf("invalid VLESS header: len=%d err=%v", len(header), err)
	}
	plain, err := requestHeader(id, 1, "example.com:443", "")
	if err != nil || plain[17] != 0 || plain[18] != 1 {
		t.Fatalf("invalid plain VLESS header: %v", err)
	}
	frame, err := xudpFrame("1.1.1.1:53", []byte("dns"), true)
	if err != nil {
		t.Fatal(err)
	}
	response := []byte{0, 4, 0, 0, 2, 1, 0, 3, 'o', 'k', '!'}
	packet, err := xudpRead(bytes.NewReader(response), &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53})
	if err != nil || string(packet.data) != "ok!" || packet.from.String() != "1.1.1.1:53" || len(frame) < 10 {
		t.Fatalf("invalid XUDP framing: %v", err)
	}
}

func TestPacketDeadlineAndClose(t *testing.T) {
	c := &Client{packets: make(map[*packetConn]struct{})}
	p, err := c.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, _, err := p.ReadFrom(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline: %v", err)
	}
	_ = p.Close()
	if _, _, err := p.ReadFrom(b[:]); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected closed packet socket: %v", err)
	}
}

func TestUDP443RestrictedOnlyByVision(t *testing.T) {
	owner := &Client{settings: accesskey.VLESS{Flow: ""}}
	packet := &packetConn{owner: owner, closed: true}
	address := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443}
	if _, err := packet.WriteTo([]byte("test"), address); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("plain VLESS incorrectly restricted UDP/443: %v", err)
	}
	owner.settings.Flow = "xtls-rprx-vision"
	if _, err := packet.WriteTo([]byte("test"), address); err == nil || errors.Is(err, net.ErrClosed) {
		t.Fatalf("Vision failed to restrict UDP/443: %v", err)
	}
}

func TestVisionUnpaddingAcrossReads(t *testing.T) {
	id, _ := userID("123e4567-e89b-12d3-a456-426614174000")
	v := &visionConn{id: id, firstRead: true, readPadding: true}
	frame := append(id[:], 1, 0, 5, 0, 2)
	frame = append(frame, []byte("hello")...)
	frame = append(frame, 0, 0)
	for _, b := range frame {
		v.decode([]byte{b})
	}
	if got := string(v.readBuf); got != "hello" || v.readPadding {
		t.Fatalf("Vision framing: got=%q padding=%v", got, v.readPadding)
	}
}
