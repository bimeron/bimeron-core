package wireguard

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"bimeron/internal/wireguard/wgtest"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// reservedPeer models a peer that verifies the on-wire stamp and normalizes
// the header before handing packets to the reference server.
func reservedPeer(t testing.TB, server *wgtest.Server, reserved [3]byte, forceCookie bool) (netip.AddrPort, *atomic.Int32) {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	cookie := new(device.CookieChecker)
	cookie.Init(device.NoisePublicKey(server.Key.Public))
	retries := new(atomic.Int32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var client netip.AddrPort
		buf := make([]byte, 65535)
		for {
			n, from, err := socket.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n < 4 {
				continue
			}
			packet := buf[:n]
			if from == server.Addr {
				if client.IsValid() {
					copy(packet[1:4], reserved[:])
					_, _ = socket.WriteToUDPAddrPort(packet, client)
				}
				continue
			}
			if !bytes.Equal(packet[1:4], reserved[:]) {
				continue
			}
			clear(packet[1:4])
			if forceCookie && packet[0] == byte(device.MessageInitiationType) {
				if n != device.MessageInitiationSize || !cookie.CheckMAC1(packet) {
					continue
				}
				source, _ := from.MarshalBinary()
				if !cookie.CheckMAC2(packet, source) {
					reply, err := cookie.CreateReply(packet, binary.LittleEndian.Uint32(packet[4:8]), source, device.MessageCookieReplyType)
					if err != nil {
						t.Error(err)
						return
					}
					var wire bytes.Buffer
					if err := binary.Write(&wire, binary.LittleEndian, reply); err != nil {
						t.Error(err)
						return
					}
					copy(wire.Bytes()[1:4], reserved[:])
					_, _ = socket.WriteToUDPAddrPort(wire.Bytes(), from)
					continue
				}
				retries.Add(1)
			}
			client = from
			_, _ = socket.WriteToUDPAddrPort(packet, server.Addr)
		}
	}()
	t.Cleanup(func() {
		_ = socket.Close()
		<-done
	})
	return socket.LocalAddr().(*net.UDPAddr).AddrPort(), retries
}

func TestReservedHandshakeCookieTrafficReconnect(t *testing.T) {
	key := wgtest.NewKeyPair(t)
	server := wgtest.StartUpstream(t, key)
	endpoint, retries := reservedPeer(t, server, [3]byte{0, 12, 255}, true)
	text := strings.Replace(server.ClientText(key, "0.0.0.0/0, ::/0"), server.Addr.String(), endpoint.String(), 1)
	text += "\nReserved = 0, 12, 255\n"
	for attempt := 1; attempt <= 2; attempt++ {
		client := startClient(t, text, "")
		echoTCP(t, client, "10.77.0.1:7", 64<<10)
		echoUDP(t, client, netip.MustParseAddrPort("[fd77::1]:7"), 1200)
		if retries.Load() < int32(attempt) {
			t.Fatal("reference peer did not validate the cookie retry MAC2")
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkReservedBind(b *testing.B) {
	for _, tc := range []struct {
		name     string
		reserved [3]byte
	}{{"zero", [3]byte{}}, {"nonzero", [3]byte{0, 12, 255}}} {
		b.Run(tc.name, func(b *testing.B) {
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				b.Fatal(err)
			}
			defer peer.Close()
			lc := new(net.ListenConfig)
			bind := NewBind(lc.ListenPacket, peer.LocalAddr().(*net.UDPAddr).AddrPort(), 0, tc.reserved)
			defer bind.Close()
			receivers, _, err := bind.Open(0)
			if err != nil {
				b.Fatal(err)
			}
			bufs := [][]byte{make([]byte, 1280)}
			received := [][]byte{make([]byte, 1280)}
			sizes := make([]int, 1)
			endpoints := make([]conn.Endpoint, 1)
			b.ReportAllocs()
			b.SetBytes(int64(len(bufs[0]) * 2))
			for b.Loop() {
				if err := bind.Send(bufs, nil); err != nil {
					b.Fatal(err)
				}
				n, from, err := peer.ReadFromUDPAddrPort(received[0])
				if err != nil {
					b.Fatal(err)
				}
				if _, err := peer.WriteToUDPAddrPort(received[0][:n], from); err != nil {
					b.Fatal(err)
				}
				if _, err := receivers[0](received, sizes, endpoints); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
