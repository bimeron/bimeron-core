package core

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func packetChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) != 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func TestPacketPortTCPAndClose(t *testing.T) {
	_, port, err := NewPacketEngine(Options{}, PacketOptions{MTU: 1420, Outbound: func(context.Context) (PacketNetwork, error) { return PacketNetwork{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	p := &packetPlatform{port: port}
	l, err := p.Open(context.Background(), DefaultConfig(), &flowRouter{}, func(string, string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	packet := make([]byte, 40)
	packet[0], packet[8], packet[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(packet[2:], 40)
	copy(packet[12:], []byte{198, 18, 0, 1})
	copy(packet[16:], []byte{203, 0, 113, 7})
	binary.BigEndian.PutUint16(packet[20:], 40000)
	binary.BigEndian.PutUint16(packet[22:], 80)
	packet[32], packet[33] = 0x50, 2
	binary.BigEndian.PutUint16(packet[34:], 65535)
	pseudo := append([]byte(nil), packet[12:20]...)
	pseudo = append(pseudo, 0, 6, 0, 20)
	pseudo = append(pseudo, packet[20:]...)
	binary.BigEndian.PutUint16(packet[36:], packetChecksum(pseudo))
	binary.BigEndian.PutUint16(packet[10:], packetChecksum(packet[:20]))
	if err := port.WritePacket(packet); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := port.ReadPacket(ctx)
	if err != nil || len(response) < 40 || response[33]&0x12 != 0x12 {
		t.Fatal("TCP SYN/ACK response", response, err)
	}
	packet6 := make([]byte, 60)
	packet6[0], packet6[6], packet6[7] = 0x60, 6, 64
	binary.BigEndian.PutUint16(packet6[4:], 20)
	copy(packet6[8:], []byte{0xfd, 0xfe, 0x52, 0x4c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(packet6[24:], []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7})
	copy(packet6[40:], packet[20:])
	packet6[56], packet6[57] = 0, 0
	pseudo6 := append([]byte(nil), packet6[8:40]...)
	pseudo6 = append(pseudo6, 0, 0, 0, 20, 0, 0, 0, 6)
	pseudo6 = append(pseudo6, packet6[40:]...)
	binary.BigEndian.PutUint16(packet6[56:], packetChecksum(pseudo6))
	if err := port.WritePacket(packet6); err != nil {
		t.Fatal(err)
	}
	response, err = port.ReadPacket(ctx)
	if err != nil || len(response) < 60 || response[0]>>4 != 6 || response[53]&0x12 != 0x12 {
		t.Fatal("IPv6 SYN/ACK response", response, err)
	}
	for _, bad := range [][]byte{nil, {0x70}, make([]byte, 20)} {
		if !errors.Is(port.WritePacket(bad), ErrInvalidPacket) {
			t.Fatal("accepted invalid packet")
		}
	}
	port.Close()
	if !errors.Is(port.WritePacket(packet), ErrPacketPortClosed) {
		t.Fatal("accepted closed port write")
	}
	if _, err := port.ReadPacket(ctx); !errors.Is(err, ErrPacketPortClosed) {
		t.Fatal(err)
	}
}

func TestMemoryConfigRejectsFileAccess(t *testing.T) {
	_, err := LoadConfigData([]byte("[Profile]\nVersion = 1\n[AccessKey]\nFile = /does-not-exist/secret.key\n"))
	if err == nil || err.Error() != "in-memory configuration requires an inline key source" {
		t.Fatal(err)
	}
}
func TestPacketPortCloseUnblocksReader(t *testing.T) {
	_, port, _ := NewPacketEngine(Options{}, PacketOptions{MTU: 1420, Outbound: func(context.Context) (PacketNetwork, error) { return PacketNetwork{}, nil }})
	done := make(chan error, 1)
	go func() { _, err := port.ReadPacket(context.Background()); done <- err }()
	port.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ErrPacketPortClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("reader stuck")
	}
}
