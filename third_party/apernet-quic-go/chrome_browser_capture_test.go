package quic

import (
	"fmt"
	"os"
	"testing"

	"github.com/apernet/quic-go/internal/handshake"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

// These packets came from unmodified Chrome for Testing binaries, not uquic or
// this package. See testdata/chrome-browser-initial/README.md for provenance.
func TestChromeBrowserCapture(t *testing.T) {
	for _, tc := range []struct {
		version, family string
		packets         int
		idle            uint64
		option          string
	}{
		{"115", "ipv4", 1, 30000, "RVCM"},
		{"115", "ipv6", 1, 30000, "RVCM"},
		{"146", "ipv4", 2, 300000, "ORIG"},
		{"146", "ipv6", 2, 300000, "ORIG"},
	} {
		t.Run(tc.version+"/"+tc.family, func(t *testing.T) {
			crypto := make([]byte, 4096)
			seen := make([]bool, len(crypto))
			end := 0
			var dcid protocol.ConnectionID
			for i := 0; i < tc.packets; i++ {
				b, err := os.ReadFile(fmt.Sprintf("testdata/chrome-browser-initial/chrome-%s-%s-%d.bin", tc.version, tc.family, i))
				require.NoError(t, err)
				size := 1250
				if tc.family == "ipv6" {
					size = 1230
				}
				require.Len(t, b, size)
				hdr, packet, tail, err := wire.ParsePacket(b)
				require.NoError(t, err)
				require.Empty(t, tail)
				if i == 0 {
					dcid = hdr.DestConnectionID
				} else {
					require.Equal(t, dcid, hdr.DestConnectionID)
				}
				require.Equal(t, 8, hdr.DestConnectionID.Len())
				require.Zero(t, hdr.SrcConnectionID.Len())
				_, opener := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveServer, protocol.Version1)
				ext, plain, err := (&packetUnpacker{}).unpackLongHeaderPacket(opener, hdr, packet)
				require.NoError(t, err)
				require.Equal(t, protocol.PacketNumber(i+1), ext.PacketNumber)
				for len(plain) > 0 {
					typ := plain[0]
					plain = plain[1:]
					if typ == 0 || typ == 1 {
						continue
					}
					require.Equal(t, byte(6), typ)
					offset, n, err := quicvarint.Parse(plain)
					require.NoError(t, err)
					plain = plain[n:]
					length, n, err := quicvarint.Parse(plain)
					require.NoError(t, err)
					plain = plain[n:]
					require.LessOrEqual(t, int(length), len(plain))
					require.LessOrEqual(t, int(offset+length), len(crypto))
					for j := 0; j < int(length); j++ {
						at := int(offset) + j
						require.False(t, seen[at], "overlapping CRYPTO")
						crypto[at], seen[at] = plain[j], true
					}
					end = max(end, int(offset+length))
					plain = plain[length:]
				}
			}
			for _, ok := range seen[:end] {
				require.True(t, ok, "missing CRYPTO byte")
			}
			hello := cryptobyte.String(crypto[:end])
			var typ uint8
			var body cryptobyte.String
			require.True(t, hello.ReadUint8(&typ) && hello.ReadUint24LengthPrefixed(&body) && hello.Empty())
			require.Equal(t, uint8(1), typ)
			require.True(t, body.Skip(34))
			var sid, suites, compression, extensions cryptobyte.String
			require.True(t, body.ReadUint8LengthPrefixed(&sid) && body.ReadUint16LengthPrefixed(&suites) && body.ReadUint8LengthPrefixed(&compression) && body.ReadUint16LengthPrefixed(&extensions) && body.Empty())
			fields := map[uint16][]byte{}
			for !extensions.Empty() {
				var id uint16
				var value cryptobyte.String
				require.True(t, extensions.ReadUint16(&id) && extensions.ReadUint16LengthPrefixed(&value))
				fields[id] = value
			}
			require.Contains(t, fields, uint16(65037)) // ECH GREASE in both browser versions
			if tc.version == "146" {
				require.Equal(t, []byte{0, 0}, fields[51764])
			}
			params := map[uint64][]byte{}
			for b := fields[57]; len(b) > 0; {
				id, n, err := quicvarint.Parse(b)
				require.NoError(t, err)
				b = b[n:]
				length, n, err := quicvarint.Parse(b)
				require.NoError(t, err)
				b = b[n:]
				require.LessOrEqual(t, int(length), len(b))
				params[id], b = b[:length], b[length:]
			}
			idle, _, err := quicvarint.Parse(params[1])
			require.NoError(t, err)
			require.Equal(t, tc.idle, idle)
			require.Equal(t, []byte(tc.option), params[0x3128])
			_, hasRTT := params[0x3127]
			require.False(t, hasRTT)
		})
	}
}
