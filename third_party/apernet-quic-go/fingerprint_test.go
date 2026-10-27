package quic

import (
	"bytes"
	"context"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/qerr"
	"github.com/apernet/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
	"time"
)

func TestFingerprintRuntimeLimits(t *testing.T) {
	c := populateConfig(&Config{Fingerprint: QUICFirefox116})
	require.EqualValues(t, 0xc00000, c.InitialStreamReceiveWindow)
	require.EqualValues(t, 0x1800000, c.InitialConnectionReceiveWindow)
	require.EqualValues(t, 16, c.MaxIncomingStreams)
	require.EqualValues(t, 16, c.MaxIncomingUniStreams)
	require.True(t, c.EnableDatagrams)
	require.False(t, c.OmitMaxDatagramFrameSize)
	require.Equal(t, 30*time.Second, c.MaxIdleTimeout)
	require.False(t, c.ChromeParrot)
	require.Error(t, validateConfig(&Config{Fingerprint: "fixture-invalid"}))
	require.Error(t, validateConfig(&Config{Fingerprint: QUICFirefox116, ChromeParrot: true}))
	require.True(t, populateConfig(&Config{Fingerprint: QUICChrome}).ChromeParrot)
	// Preserve ordinary limits; a Firefox connection alone accepts eight IDs.
	for _, limit := range []int{protocol.MaxActiveConnectionIDs, 8} {
		m := newConnIDManager(protocol.ParseConnectionID([]byte{0}), func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, func(wire.Frame) {})
		m.activeLimit = limit
		for i := 1; i < limit; i++ {
			f := &wire.NewConnectionIDFrame{SequenceNumber: uint64(i), ConnectionID: protocol.ParseConnectionID([]byte{byte(i)})}
			require.NoError(t, m.Add(f))
			require.NoError(t, m.Add(f))
		}
		var failure *qerr.TransportError
		require.ErrorAs(t, m.Add(&wire.NewConnectionIDFrame{SequenceNumber: uint64(limit), ConnectionID: protocol.ParseConnectionID([]byte{byte(limit)})}), &failure)
		require.Equal(t, qerr.ConnectionIDLimitError, failure.ErrorCode)
	}
}

func TestFirefoxLargeReceive(t *testing.T) {
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer socket.Close()
	raw, err := wrapConn(socket, false)
	require.NoError(t, err)
	raw.(interface{ enableLargeReceive() }).enableLargeReceive()
	sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer sender.Close()
	payload := bytes.Repeat([]byte{42}, 16000)
	_, err = sender.WriteTo(payload, socket.LocalAddr())
	require.NoError(t, err)
	require.NoError(t, raw.SetReadDeadline(time.Now().Add(time.Second)))
	packet, err := raw.ReadPacket()
	require.NoError(t, err)
	defer packet.buffer.Release()
	require.Equal(t, payload, packet.data)
}

func TestFirefoxGreasedBitParsing(t *testing.T) {
	b := captureFingerprintInitial(t, "udp4", QUICFirefox116)
	b[0] &= ^byte(0x40)
	_, _, _, err := wire.ParsePacket(b)
	require.Error(t, err)
	_, _, _, err = wire.ParsePacket(b, true)
	require.NoError(t, err)
	// Header acceptance does not modify the authenticated bytes or bypass AEAD.
	short := []byte{0, 1, 2, 3, 0}
	_, _, _, _, err = wire.ParseShortHeader(short, 3)
	require.Error(t, err)
	_, _, _, _, err = wire.ParseShortHeader(short, 3, true)
	require.NoError(t, err)
}

func TestChromeTransportReceive1472(t *testing.T) {
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer socket.Close()
	tr := &Transport{Conn: socket, ConnectionIDGenerator: ZeroLengthConnectionIDGenerator{}}
	defer tr.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err = tr.ReadNonQUICPacket(ctx, make([]byte, 1472))
	require.ErrorIs(t, err, context.Canceled)
	sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer sender.Close()
	payload := bytes.Repeat([]byte{42}, 1472)
	_, err = sender.WriteTo(payload, socket.LocalAddr())
	require.NoError(t, err)
	ctx, cancel = context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	b := make([]byte, 2000)
	n, _, err := tr.ReadNonQUICPacket(ctx, b)
	require.NoError(t, err)
	require.Equal(t, payload, b[:n])
}
