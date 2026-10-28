package quic

import (
	"encoding/binary"
	"testing"

	"github.com/apernet/quic-go/internal/handshake"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

// Expectations come from the Chrome for Testing captures in testdata and the
// versioned uquic reference, independently of the production marshaller.
// Random bytes and shuffled order are normalized.
func TestChromeVersionedWire(t *testing.T) {
	for _, fp := range []QUICFingerprint{QUICChrome115, QUICChrome146} {
		for _, network := range []string{"udp4", "udp6"} {
			t.Run(string(fp)+"/"+network, func(t *testing.T) {
				count := 1
				if fp == QUICChrome146 {
					count = 2
				}
				packets := captureFingerprintFlight(t, network, fp, count)
				crypto := make([]byte, 4096)
				seen := make([]bool, len(crypto))
				end := 0
				for i, b := range packets {
					size := 1250
					if network == "udp6" {
						size = 1230
					}
					require.Len(t, b, size)
					hdr, packet, tail, err := wire.ParsePacket(b)
					require.NoError(t, err)
					require.Empty(t, tail)
					require.Equal(t, protocol.Version1, hdr.Version)
					require.Equal(t, 8, hdr.DestConnectionID.Len())
					require.Zero(t, hdr.SrcConnectionID.Len())
					require.Empty(t, hdr.Token)
					_, opener := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveServer, protocol.Version1)
					ext, plain, err := (&packetUnpacker{}).unpackLongHeaderPacket(opener, hdr, packet)
					require.NoError(t, err)
					require.Equal(t, protocol.PacketNumber(i+1), ext.PacketNumber)
					pnLen := protocol.PacketNumberLen1
					if i == 1 {
						pnLen = protocol.PacketNumberLen2
					}
					require.Equal(t, pnLen, ext.PacketNumberLen)
					pings, frames, padding := 0, 0, 0
					for len(plain) > 0 {
						typ := plain[0]
						plain = plain[1:]
						switch typ {
						case 0:
							padding++
						case 1:
							pings++
						case 6:
							offset, n, e := quicvarint.Parse(plain)
							require.NoError(t, e)
							plain = plain[n:]
							length, n, e := quicvarint.Parse(plain)
							require.NoError(t, e)
							plain = plain[n:]
							require.LessOrEqual(t, int(offset+length), len(crypto))
							require.LessOrEqual(t, int(length), len(plain))
							for j := 0; j < int(length); j++ {
								at := int(offset) + j
								require.False(t, seen[at], "overlapping CRYPTO")
								crypto[at] = plain[j]
								seen[at] = true
							}
							end = max(end, int(offset+length))
							plain = plain[length:]
							frames++
						default:
							t.Fatalf("unexpected Initial frame type %d", typ)
						}
					}
					require.Positive(t, padding)
					if fp == QUICChrome115 {
						require.LessOrEqual(t, pings, 10)
						require.GreaterOrEqual(t, frames, 1)
						require.LessOrEqual(t, frames, 10)
					} else {
						require.GreaterOrEqual(t, pings, 1)
						require.LessOrEqual(t, pings, 4)
						require.GreaterOrEqual(t, frames, 6)
						require.LessOrEqual(t, frames, 14)
					}
				}
				for _, v := range seen[:end] {
					require.True(t, v, "missing CRYPTO byte")
				}
				hello := cryptobyte.String(crypto[:end])
				var typ uint8
				var body cryptobyte.String
				require.True(t, hello.ReadUint8(&typ) && hello.ReadUint24LengthPrefixed(&body) && hello.Empty())
				require.Equal(t, uint8(1), typ)
				require.True(t, body.Skip(34))
				var sid, suites, compression, extensions cryptobyte.String
				require.True(t, body.ReadUint8LengthPrefixed(&sid) && body.ReadUint16LengthPrefixed(&suites) && body.ReadUint8LengthPrefixed(&compression) && body.ReadUint16LengthPrefixed(&extensions) && body.Empty())
				require.Empty(t, sid)
				require.Equal(t, []byte{0x13, 1, 0x13, 2, 0x13, 3}, []byte(suites))
				require.Equal(t, []byte{0}, []byte(compression))
				fields := map[uint16][]byte{}
				for !extensions.Empty() {
					var id uint16
					var value cryptobyte.String
					require.True(t, extensions.ReadUint16(&id) && extensions.ReadUint16LengthPrefixed(&value))
					_, exists := fields[id]
					require.False(t, exists)
					fields[id] = value
				}
				want := []uint16{0, 10, 13, 16, 27, 43, 45, 51, 57}
				if fp == QUICChrome115 {
					want = append(want, 17513, 65037)
				} else {
					want = append(want, 17613, 65037, 51764)
				}
				var ids []uint16
				for id := range fields {
					ids = append(ids, id)
				}
				require.ElementsMatch(t, want, ids)
				if fp == QUICChrome146 {
					require.Equal(t, []byte{0, 0}, fields[51764])
				}
				require.Equal(t, []byte{0, 3, 2, 'h', '3'}, fields[16])
				require.Equal(t, []byte{2, 3, 4}, fields[43])
				require.Equal(t, []byte{1, 1}, fields[45])
				require.Equal(t, []byte{0, 18, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1, 2, 1}, fields[13])
				alps := uint16(17513)
				if fp == QUICChrome146 {
					alps = 17613
				}
				require.Equal(t, []byte{0, 3, 2, 'h', '3'}, fields[alps])
				require.Equal(t, []byte{2, 0, 2}, fields[27])
				require.Contains(t, string(fields[0]), "fixture.example")
				curves := []byte{0, 6, 0, 29, 0, 23, 0, 24}
				if fp == QUICChrome146 {
					curves = []byte{0, 8, 0x11, 0xec, 0, 29, 0, 23, 0, 24}
				}
				require.Equal(t, curves, fields[10])
				shares := cryptobyte.String(fields[51])
				var list cryptobyte.String
				require.True(t, shares.ReadUint16LengthPrefixed(&list) && shares.Empty())
				var groups []uint16
				var lengths []int
				for !list.Empty() {
					var group uint16
					var key cryptobyte.String
					require.True(t, list.ReadUint16(&group) && list.ReadUint16LengthPrefixed(&key))
					groups = append(groups, group)
					lengths = append(lengths, len(key))
				}
				if fp == QUICChrome115 {
					require.Equal(t, []uint16{29}, groups)
					require.Equal(t, []int{32}, lengths)
				} else {
					require.Equal(t, []uint16{0x11ec, 29}, groups)
					require.Equal(t, []int{1216, 32}, lengths)
				}
				params := map[uint64][]byte{}
				tp := fields[57]
				for len(tp) > 0 {
					id, n, e := quicvarint.Parse(tp)
					require.NoError(t, e)
					tp = tp[n:]
					size, n, e := quicvarint.Parse(tp)
					require.NoError(t, e)
					tp = tp[n:]
					require.LessOrEqual(t, int(size), len(tp))
					_, exists := params[id]
					require.False(t, exists)
					params[id] = tp[:size]
					tp = tp[size:]
				}
				idle := uint64(30000)
				if fp == QUICChrome146 {
					idle = 300000
				}
				for id, want := range map[uint64]uint64{1: idle, 3: 1472, 4: 15728640, 5: 6291456, 6: 6291456, 7: 6291456, 8: 100, 9: 103, 32: 65536} {
					value, n, e := quicvarint.Parse(params[id])
					require.NoError(t, e)
					require.Equal(t, want, value)
					require.Equal(t, n, len(params[id]))
					delete(params, id)
				}
				require.Contains(t, params, uint64(15))
				require.Empty(t, params[15])
				delete(params, 15)
				versionID := uint64(0x11)
				if fp == QUICChrome115 {
					versionID = 0xff73db
					require.Equal(t, []byte{0, 0, 0, 1}, params[0x4752])
					delete(params, 0x4752)
					require.Equal(t, []byte("RVCM"), params[0x3128])
				} else {
					require.Equal(t, []byte("ORIG"), params[0x3128])
				}
				delete(params, 0x3128)
				versions := params[versionID]
				require.Len(t, versions, 12)
				require.Equal(t, uint32(1), binary.BigEndian.Uint32(versions))
				delete(params, versionID)
				require.Len(t, params, 1)
				for id, v := range params {
					require.Equal(t, uint64(0), (id-27)%31)
					require.LessOrEqual(t, len(v), 15)
				}
			})
		}
	}
}
