package ss2022

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

// TestXrayInterop exercises the independent Xray server when BIMERON_XRAY_BIN is set.
func TestXrayInterop(t *testing.T) {
	bin := os.Getenv("BIMERON_XRAY_BIN")
	if bin == "" {
		t.Skip("BIMERON_XRAY_BIN is not set")
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, addr, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(b[:n], addr)
		}
	}()
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			key := make([]byte, 32)
			if method == "2022-blake3-aes-128-gcm" {
				key = key[:16]
			}
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			password := base64.StdEncoding.EncodeToString(key)
			// Windows may reserve a TCP ephemeral port for UDP. Allocate UDP first.
			var port int
			for i := 0; i < 20; i++ {
				probeUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port = probeUDP.LocalAddr().(*net.UDPAddr).Port
				probeTCP, tcpErr := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
				_ = probeUDP.Close()
				if tcpErr == nil {
					_ = probeTCP.Close()
					break
				}
				if i == 19 {
					t.Fatalf("no available TCP/UDP port: %v", tcpErr)
				}
			}
			config := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "shadowsocks", "settings": map[string]any{"method": method, "password": password, "network": "tcp,udp"}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
			data, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "xray.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cmd := exec.CommandContext(ctx, bin, "run", "-config", path)
			log, err := os.Create(filepath.Join(filepath.Dir(path), "xray.log"))
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stdout, cmd.Stderr = log, log
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = cmd.Wait(); _ = log.Close() }()
			server := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			for i := 0; i < 50; i++ {
				c, err := net.DialTimeout("tcp", server, time.Second)
				if err == nil {
					_ = c.Close()
					break
				}
				if i == 49 {
					_ = log.Sync()
					output, _ := os.ReadFile(log.Name())
					t.Fatalf("Xray did not start: %v: %s", err, output)
				}
				time.Sleep(100 * time.Millisecond)
			}
			client, err := New(accesskey.Endpoint{Host: "127.0.0.1", Port: port, Cipher: method, Secret: password}, net.Dialer{Timeout: 3 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			stream, err := client.DialStream(context.Background(), tcp.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := stream.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 4)
			if _, err := io.ReadFull(stream, b); err != nil || string(b) != "ping" {
				t.Fatalf("TCP reply %q: %v", b, err)
			}
			large := bytes.Repeat([]byte("a"), 70000)
			if _, err := stream.Write(large); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(large))
			if _, err := io.ReadFull(stream, reply); err != nil || !bytes.Equal(reply, large) {
				t.Fatalf("large TCP reply: %v", err)
			}
			packet, err := client.PacketListener().ListenPacket(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			_ = packet.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := packet.WriteTo([]byte("pong"), udp.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			n, _, err := packet.ReadFrom(b)
			if err != nil || string(b[:n]) != "pong" {
				t.Fatalf("UDP reply %q: %v", b[:n], err)
			}
		})
	}
}

func TestReplayWindow(t *testing.T) {
	w := replayWindow{seen: make(map[uint64]struct{})}
	if !w.accept(0) || w.accept(0) || !w.accept(1025) || w.accept(0) || !w.accept(1024) || w.accept(1024) {
		t.Fatal("UDP replay window accepted a duplicate or rejected a fresh packet")
	}
}
