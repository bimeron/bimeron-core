package wireguard

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/proxy"
	"bimeron/internal/wireguard/wgtest"
	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgnetstack "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	sscore "github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// Benchmarks compare bulk TCP through one connection over loopback. They
// report MB/s, CPU time per MiB (Linux and macOS) and heap growth. All
// servers run in this process, so absolute numbers include server work;
// compare rows with each other, not with link speeds.

const bulkChunk = 1 << 20

// bulk sends one MiB and reads the echo back.
func bulk(b *testing.B, conn net.Conn) {
	payload := make([]byte, bulkChunk)
	got := make([]byte, bulkChunk)
	errc := make(chan error, 1)
	go func() { _, err := conn.Write(payload); errc <- err }()
	if _, err := io.ReadFull(conn, got); err != nil {
		b.Fatal(err)
	}
	if err := <-errc; err != nil {
		b.Fatal(err)
	}
}

func measure(b *testing.B, dial func() net.Conn) {
	conn := dial()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	bulk(b, conn) // warm up the path and windows
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	cpu := processCPU()
	b.SetBytes(bulkChunk)
	b.ResetTimer()
	for b.Loop() {
		bulk(b, conn)
	}
	b.StopTimer()
	if spent := processCPU() - cpu; spent > 0 {
		b.ReportMetric(float64(spent.Microseconds())/float64(b.N), "cpu-us/MiB")
	}
	runtime.ReadMemStats(&after)
	b.ReportMetric(float64(after.HeapInuse)/(1<<20), "heap-MiB")
}

func BenchmarkTCPBulk(b *testing.B) {
	for _, name := range []string{"wireguard", "awg-1.0", "awg-2.0", "awg-3.1"} {
		b.Run("bimeron/"+name, func(b *testing.B) {
			client := wgtest.NewKeyPair(b)
			var p wgtest.Profile
			if name != "wireguard" {
				p = wgtest.Profiles[name]
			}
			s := wgtest.StartAWG(b, client, p.Server)
			c := startClient(b, s.ClientText(client, "0.0.0.0/0, ::/0", p.Client...), "")
			measure(b, func() net.Conn {
				conn, err := c.DialStream(context.Background(), "10.77.0.1:7")
				if err != nil {
					b.Fatal(err)
				}
				return conn
			})
		})
		b.Run("native-amneziawg-go/"+name, func(b *testing.B) {
			client := wgtest.NewKeyPair(b)
			var p wgtest.Profile
			if name != "wireguard" {
				p = wgtest.Profiles[name]
			}
			s := wgtest.StartAWG(b, client, p.Server)
			tnet := nativeClient(b, client, s, p.Server)
			measure(b, func() net.Conn {
				conn, err := tnet.DialContextTCPAddrPort(context.Background(), netip.AddrPortFrom(wgtest.ServerV4, 7))
				if err != nil {
					b.Fatal(err)
				}
				return conn
			})
		})
	}
	b.Run("bimeron/shadowsocks-chacha20", func(b *testing.B) {
		echo := loopbackEcho(b)
		ss := startShadowsocks(b)
		d, err := proxy.OutlineProfile(accesskey.Profile{TCP: ss, UDP: ss}, net.Dialer{})
		if err != nil {
			b.Fatal(err)
		}
		measure(b, func() net.Conn {
			conn, err := d.DialStream(context.Background(), echo)
			if err != nil {
				b.Fatal(err)
			}
			return conn
		})
	})
}

// nativeClient is amneziawg-go as its own examples use it: the standard
// batched bind and the netstack, without Bimeron's bind or scope.
func nativeClient(b *testing.B, client wgtest.KeyPair, s *wgtest.Server, awg []string) *awgnetstack.Net {
	tun, tnet, err := awgnetstack.CreateNetTUN([]netip.Addr{wgtest.ClientV4}, nil, 1420)
	if err != nil {
		b.Fatal(err)
	}
	dev := awgdevice.NewDevice(tun, awgconn.NewStdNetBind(), awgdevice.NewLogger(awgdevice.LogLevelSilent, ""))
	uapi := fmt.Sprintf("private_key=%s\n%spublic_key=%s\npreshared_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1\n",
		wgtest.Hex(client.Private), wgtest.JoinLines(awg), wgtest.Hex(s.Key.Public), wgtest.Hex(s.PSK), s.Addr)
	if err := dev.IpcSet(uapi); err != nil {
		b.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(dev.Close)
	return tnet
}

func loopbackEcho(b *testing.B) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

// startShadowsocks runs a minimal AEAD Shadowsocks TCP relay on loopback.
func startShadowsocks(b *testing.B) accesskey.Endpoint {
	const cipher, password = "chacha20-ietf-poly1305", "benchmark-only-password"
	ciph, err := sscore.PickCipher("CHACHA20-IETF-POLY1305", nil, password)
	if err != nil {
		b.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc := ciph.StreamConn(c)
				target, err := socks.ReadAddr(sc)
				if err != nil {
					return
				}
				up, err := net.Dial("tcp", target.String())
				if err != nil {
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(up, sc) }()
				_, _ = io.Copy(sc, up)
			}()
		}
	}()
	port, _ := strconv.Atoi(l.Addr().(*net.TCPAddr).AddrPort().String()[len("127.0.0.1:"):])
	return accesskey.Endpoint{Host: "127.0.0.1", Port: port, Cipher: cipher, Secret: password}
}
