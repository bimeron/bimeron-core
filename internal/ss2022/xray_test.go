package ss2022

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
			size := 32
			if method == "2022-blake3-aes-128-gcm" {
				size = 16
			}
			freshKey := func() string {
				key := make([]byte, size)
				if _, err := rand.Read(key); err != nil {
					t.Fatal(err)
				}
				return base64.StdEncoding.EncodeToString(key)
			}
			scenarios := []string{"single"}
			if method != "2022-blake3-chacha20-poly1305" {
				scenarios = append(scenarios, "multi-user", "relay-multi-user")
			}
			for _, scenario := range scenarios {
				t.Run(scenario, func(t *testing.T) {
					userKeys := []string{freshKey()}
					identityKey, relayKey := freshKey(), freshKey()
					port := xraySSPort(t)
					settings := map[string]any{"method": method, "password": userKeys[0], "network": "tcp,udp"}
					if scenario != "single" {
						userKeys = append(userKeys, freshKey())
						settings["password"] = identityKey
						settings["clients"] = []any{map[string]any{"password": userKeys[0], "email": "user0"}, map[string]any{"password": userKeys[1], "email": "user1"}}
					}
					inbound := func(port int, settings map[string]any) any {
						return map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "shadowsocks", "settings": settings}
					}
					inbounds := []any{inbound(port, settings)}
					if scenario == "relay-multi-user" {
						relayPort := xraySSPort(t)
						for relayPort == port {
							relayPort = xraySSPort(t)
						}
						relay := map[string]any{"method": method, "password": relayKey, "network": "tcp,udp", "clients": []any{map[string]any{"password": identityKey, "address": "127.0.0.1", "port": port}}}
						inbounds = append(inbounds, inbound(relayPort, relay))
						port = relayPort
					}
					config := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": inbounds, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
					startSSXray(t, bin, port, config)
					for i, key := range userKeys {
						chain := key
						if scenario != "single" {
							chain = identityKey + ":" + chain
						}
						if scenario == "relay-multi-user" {
							chain = relayKey + ":" + chain
						}
						endpoint := accesskey.Endpoint{Host: "127.0.0.1", Port: port, Cipher: method, Secret: chain}
						t.Run(strconv.Itoa(i), func(t *testing.T) {
							client, err := New(endpoint, net.Dialer{Timeout: 3 * time.Second})
							if err != nil {
								t.Fatal(err)
							}
							exchangeSSXray(t, client, tcp.Addr().String(), udp.LocalAddr())
						})
					}
					if scenario != "single" {
						valid := []string{identityKey, userKeys[0]}
						if scenario == "relay-multi-user" {
							valid = append([]string{relayKey}, valid...)
						}
						for _, failure := range []string{"identity", "user", "order"} {
							t.Run("reject-"+failure, func(t *testing.T) {
								keys := append([]string(nil), valid...)
								switch failure {
								case "identity":
									keys[0] = freshKey()
								case "user":
									keys[len(keys)-1] = freshKey()
								case "order":
									keys[0], keys[len(keys)-1] = keys[len(keys)-1], keys[0]
								}
								client, err := New(accesskey.Endpoint{Host: "127.0.0.1", Port: port, Cipher: method, Secret: strings.Join(keys, ":")}, net.Dialer{Timeout: time.Second})
								if err != nil {
									t.Fatal(err)
								}
								ctx, cancel := context.WithTimeout(context.Background(), time.Second)
								defer cancel()
								stream, err := client.DialStream(ctx, tcp.Addr().String())
								if err == nil {
									defer stream.Close()
									_ = stream.SetDeadline(time.Now().Add(250 * time.Millisecond))
									_, _ = stream.Write([]byte("reject"))
									if _, err := stream.Read(make([]byte, 32)); err == nil {
										t.Fatal("invalid chain received a TCP response")
									}
								}
								packet, err := client.PacketListener().ListenPacket(context.Background())
								if err != nil {
									t.Fatal(err)
								}
								defer packet.Close()
								_ = packet.SetDeadline(time.Now().Add(250 * time.Millisecond))
								if _, err := packet.WriteTo([]byte("reject"), udp.LocalAddr()); err != nil {
									t.Fatal(err)
								}
								if _, _, err := packet.ReadFrom(make([]byte, 32)); err == nil {
									t.Fatal("invalid chain received a UDP response")
								}
							})
						}
					}
				})
			}
		})
	}
}

func xraySSPort(t *testing.T) int {
	t.Helper()
	// Avoid Windows-reserved ephemeral TCP ranges while probing both protocols.
	var port int
	for i := 0; i < 100; i++ {
		var random [2]byte
		if _, err := rand.Read(random[:]); err != nil {
			t.Fatal(err)
		}
		port = 20000 + int(binary.BigEndian.Uint16(random[:]))%25000
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		probeUDP, err := net.ListenPacket("udp", addr)
		if err != nil {
			continue
		}
		probeTCP, err := net.Listen("tcp", addr)
		_ = probeUDP.Close()
		if err == nil {
			_ = probeTCP.Close()
			return port
		}
	}
	t.Fatal("no available TCP/UDP port")
	return port
}

func startSSXray(t *testing.T, bin string, port int, config map[string]any) {
	t.Helper()
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
	t.Cleanup(func() { cancel(); _ = cmd.Wait(); _ = log.Close() })
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
}

func exchangeSSXray(t *testing.T, client *Client, tcpTarget string, udpTarget net.Addr) {
	t.Helper()
	stream, err := client.DialStream(context.Background(), tcpTarget)
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
	if _, err := packet.WriteTo([]byte("pong"), udpTarget); err != nil {
		t.Fatal(err)
	}
	n, _, err := packet.ReadFrom(b)
	if err != nil || string(b[:n]) != "pong" {
		t.Fatalf("UDP reply %q: %v", b[:n], err)
	}
}

func TestReplayWindow(t *testing.T) {
	w := replayWindow{seen: make(map[uint64]struct{})}
	if !w.accept(0) || w.accept(0) || !w.accept(1025) || w.accept(0) || !w.accept(1024) || w.accept(1024) {
		t.Fatal("UDP replay window accepted a duplicate or rejected a fresh packet")
	}
}
