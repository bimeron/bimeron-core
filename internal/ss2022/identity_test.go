package ss2022

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

func TestIdentityWireVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/sip023.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Method                 string
			Keys                   []string
			Salt, Header, TCP, UDP string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Method, func(t *testing.T) {
			keys := make([]string, len(v.Keys))
			for i, key := range v.Keys {
				keys[i] = base64.StdEncoding.EncodeToString(decode(key))
			}
			for depth := 0; depth <= 2; depth++ {
				t.Run(fmt.Sprint(depth), func(t *testing.T) {
					// Use suffixes so the terminal user key stays the same.
					start := 2 - depth
					server, err := net.ListenPacket("udp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer server.Close()
					endpoint := server.LocalAddr().(*net.UDPAddr)
					c, err := New(accesskey.Endpoint{Host: "127.0.0.1", Port: endpoint.Port, Cipher: v.Method, Secret: strings.Join(keys[start:], ":")}, net.Dialer{})
					if err != nil {
						t.Fatal(err)
					}
					salt := decode(v.Salt)
					if got := c.appendTCPIdentities(nil, salt); !bytes.Equal(got, decode(v.TCP)[start*16:]) {
						t.Fatalf("TCP EIH %x", got)
					}
					conn, err := c.PacketListener().ListenPacket(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					p := conn.(*packetConn)
					header := decode(v.Header)
					copy(p.sessionID[:], header[:8])
					p.packetID = binary.BigEndian.Uint64(header[8:])
					p.sendAEAD, err = c.aead(p.sessionID[:])
					if err != nil {
						t.Fatal(err)
					}
					target := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
					if _, err := p.WriteTo([]byte("payload"), target); err != nil {
						t.Fatal(err)
					}
					_ = server.SetReadDeadline(time.Now().Add(time.Second))
					packet := make([]byte, 65535)
					n, _, err := server.ReadFrom(packet)
					if err != nil {
						t.Fatal(err)
					}
					prefix := make([]byte, 16)
					p.sendBlock.Encrypt(prefix, header)
					prefix = append(prefix, decode(v.UDP)[16+start*16:]...)
					if !bytes.Equal(packet[:len(prefix)], prefix) {
						t.Fatalf("UDP headers %x, want %x", packet[:len(prefix)], prefix)
					}
					if depth == 2 && !bytes.Equal(prefix, decode(v.UDP)) {
						t.Fatal("separate header differs from independent vector")
					}
					plain, err := p.sendAEAD.Open(nil, header[4:], packet[len(prefix):n], nil)
					if err != nil || !bytes.HasSuffix(plain, []byte("payload")) {
						t.Fatalf("UDP user-key payload: %v", err)
					}
					// Account for every EIH at the exact UDP datagram limit.
					maxPayload := 65507 - 16 - depth*16 - 16 - 11 - 7
					if _, err := p.WriteTo(make([]byte, maxPayload), target); err != nil {
						t.Fatal(err)
					}
					if _, err := p.WriteTo(make([]byte, maxPayload+1), target); err == nil {
						t.Fatal("oversized UDP packet accepted")
					}
				})
			}
		})
	}
}

func BenchmarkTCPIdentityHeaders(b *testing.B) {
	for _, size := range []int{16, 32} {
		for _, depth := range []int{0, 1, 4} {
			b.Run(fmt.Sprintf("AES%d/depth%d", size*8, depth), func(b *testing.B) {
				key := base64.StdEncoding.EncodeToString(make([]byte, size))
				c, err := New(accesskey.Endpoint{Host: "localhost", Port: 8388, Cipher: fmt.Sprintf("2022-blake3-aes-%d-gcm", size*8), Secret: strings.TrimSuffix(strings.Repeat(key+":", depth+1), ":")}, net.Dialer{})
				if err != nil {
					b.Fatal(err)
				}
				salt := make([]byte, size)
				packet := make([]byte, 0, depth*16)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					packet = c.appendTCPIdentities(packet[:0], salt)
				}
			})
		}
	}
}
