package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/apernet/quic-go/internal/handshake"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

// These expectations come from uquic QUICFirefox_116A, not the implementation
// under test. Capture actual UDP bytes, decrypt Initial, then inspect TLS/QUIC.
func TestFirefoxWireInitial(t *testing.T) {
	for _, fp := range []QUICFingerprint{QUICFirefox116, QUICFirefox116B, QUICFirefox116C} {
		t.Run(string(fp), func(t *testing.T) {
			for _, network := range []string{"udp4", "udp6"} {
				t.Run(network, func(t *testing.T) {
					b := captureFingerprintInitial(t, network, fp)
					require.Len(t, b, 1357)
					hdr, packet, tail, err := wire.ParsePacket(b)
					require.NoError(t, err)
					require.Equal(t, protocol.Version1, hdr.Version)
					wantDCID := 8
					if fp == QUICFirefox116B {
						wantDCID = 9
					}
					if fp == QUICFirefox116C {
						wantDCID = 15
					}
					require.Equal(t, wantDCID, hdr.DestConnectionID.Len())
					require.Equal(t, 3, hdr.SrcConnectionID.Len())
					require.Empty(t, hdr.Token)
					require.NotEmpty(t, tail)
					require.Equal(t, make([]byte, len(tail)), tail)
					_, opener := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveServer, protocol.Version1)
					ext, plain, err := (&packetUnpacker{}).unpackLongHeaderPacket(opener, hdr, packet)
					require.NoError(t, err)
					require.Equal(t, protocol.PacketNumber(0), ext.PacketNumber)
					require.Equal(t, protocol.PacketNumberLen1, ext.PacketNumberLen)
					require.Equal(t, byte(6), plain[0])
					plain = plain[1:]
					offset, l, err := quicvarint.Parse(plain)
					require.NoError(t, err)
					require.Zero(t, offset)
					plain = plain[l:]
					length, l, err := quicvarint.Parse(plain)
					require.NoError(t, err)
					plain = plain[l:]
					require.Equal(t, int(length), len(plain))
					hello := cryptobyte.String(plain)
					var typ uint8
					var body cryptobyte.String
					require.True(t, hello.ReadUint8(&typ) && hello.ReadUint24LengthPrefixed(&body) && hello.Empty())
					require.Equal(t, uint8(1), typ)
					require.True(t, body.Skip(34))
					var sid, suites, compression, extensions cryptobyte.String
					require.True(t, body.ReadUint8LengthPrefixed(&sid) && body.ReadUint16LengthPrefixed(&suites) && body.ReadUint8LengthPrefixed(&compression) && body.ReadUint16LengthPrefixed(&extensions) && body.Empty())
					require.Equal(t, []byte{0x13, 1, 0x13, 3, 0x13, 2}, []byte(suites))
					require.Equal(t, []byte{0}, []byte(compression))
					var ids []uint16
					fields := map[uint16][]byte{}
					for !extensions.Empty() {
						var id uint16
						var v cryptobyte.String
						require.True(t, extensions.ReadUint16(&id) && extensions.ReadUint16LengthPrefixed(&v))
						ids = append(ids, id)
						fields[id] = v
					}
					expected := []uint16{0, 23, 65281, 10, 16, 5, 34, 51, 43, 13, 45, 28, 57}
					if len(ids) > len(expected) {
						require.Equal(t, uint16(21), ids[len(ids)-1])
						ids = ids[:len(ids)-1]
					}
					require.Equal(t, expected, ids)
					require.Equal(t, []byte{0, 3, 2, 'h', '3'}, fields[16])
					require.Equal(t, []byte{2, 3, 4}, fields[43])
					require.Contains(t, string(fields[0]), "fixture.example")
					require.Equal(t, []byte{0, 18, 0, 29, 0, 23, 0, 24, 0, 25, 1, 0, 1, 1, 1, 2, 1, 3, 1, 4}, fields[10])
					require.Equal(t, []byte{0, 22, 4, 3, 5, 3, 6, 3, 2, 3, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 2, 1}, fields[13])
					require.Equal(t, []byte{0x40, 1}, fields[28])
					require.Equal(t, []byte{1, 1}, fields[45])
					require.Equal(t, []byte{0, 36, 0, 29, 0, 32}, fields[51][:6])
					require.Len(t, fields[51], 38)
					params := map[uint64][]byte{}
					tp := fields[57]
					for len(tp) > 0 {
						id, n, e := quicvarint.Parse(tp)
						require.NoError(t, e)
						tp = tp[n:]
						size, n, e := quicvarint.Parse(tp)
						require.NoError(t, e)
						tp = tp[n:]
						require.GreaterOrEqual(t, len(tp), int(size))
						_, duplicate := params[id]
						require.False(t, duplicate)
						params[id] = bytes.Clone(tp[:size])
						tp = tp[size:]
					}
					for id, want := range map[uint64]uint64{1: 30000, 4: 0x1800000, 5: 0xc00000, 6: 0x100000, 7: 0x100000, 8: 16, 9: 16, 11: 20, 14: 8, 32: 1200} {
						v, n, e := quicvarint.Parse(params[id])
						require.NoError(t, e)
						require.Equal(t, want, v)
						require.Equal(t, quicvarint.Len(want), n)
						delete(params, id)
					}
					require.Equal(t, hdr.SrcConnectionID.Bytes(), params[15])
					delete(params, 15)
					for _, id := range []uint64{12, 0x2ab2} {
						v, ok := params[id]
						require.True(t, ok)
						require.Empty(t, v)
						delete(params, id)
					}
					version := params[0xff73db]
					require.Len(t, version, 12)
					require.Equal(t, uint32(1), binary.BigEndian.Uint32(version[:4]))
					require.Equal(t, uint32(0x0a0a0a0a), binary.BigEndian.Uint32(version[4:8])&0x0f0f0f0f)
					require.Equal(t, uint32(1), binary.BigEndian.Uint32(version[8:]))
					delete(params, 0xff73db)
					require.Len(t, params, 1)
					for id, v := range params {
						require.Equal(t, uint64(0), (id-27)%31)
						require.Len(t, v, 2)
					}
				})
			}
		})
	}
}

func captureFingerprintInitial(t testing.TB, network string, fp QUICFingerprint) []byte {
	t.Helper()
	address := "127.0.0.1:0"
	if network == "udp6" {
		address = "[::1]:0"
	}
	server, err := net.ListenPacket(network, address)
	require.NoError(t, err)
	defer server.Close()
	socket, err := net.ListenPacket(network, address)
	require.NoError(t, err)
	defer socket.Close()
	tr := &Transport{Conn: socket}
	if fp.IsFirefox() {
		tr.ConnectionIDLength = 3
		tr.AllowQUICBitGrease = true
	} else {
		tr.ConnectionIDGenerator = ZeroLengthConnectionIDGenerator{}
	}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = tr.Dial(ctx, server.LocalAddr(), &tls.Config{ServerName: "fixture.example", NextProtos: []string{"h3"}}, &Config{Fingerprint: fp})
	}()
	require.NoError(t, server.SetReadDeadline(time.Now().Add(2*time.Second)))
	b := make([]byte, 2048)
	n, _, err := server.ReadFrom(b)
	require.NoError(t, err)
	b = b[:n]
	cancel()
	<-done
	return b
}

func TestChromeWireNegativeControl(t *testing.T) {
	b := captureFingerprintInitial(t, "udp4", QUICChrome)
	hdr, packet, tail, err := wire.ParsePacket(b)
	require.NoError(t, err)
	require.Equal(t, 0, hdr.SrcConnectionID.Len())
	require.Equal(t, 8, hdr.DestConnectionID.Len())
	require.Empty(t, tail)
	_, opener := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveServer, protocol.Version1)
	ext, _, err := (&packetUnpacker{}).unpackLongHeaderPacket(opener, hdr, packet)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(1), ext.PacketNumber)
	require.NotEqual(t, 1357, len(b))
}

// Measures complete first-Initial construction and UDP emission, including
// socket setup and TLS allocation. It is not a WAN throughput benchmark.
func BenchmarkFingerprintInitial(b *testing.B) {
	for _, fp := range []QUICFingerprint{QUICChrome, QUICFirefox116} {
		b.Run(string(fp), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				captureFingerprintInitial(b, "udp4", fp)
			}
		})
	}
}
