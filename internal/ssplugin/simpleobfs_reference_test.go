package ssplugin

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"bimeron/internal/accesskey"
	"bimeron/internal/simpleobfs"
	"bimeron/internal/testutil"
)

func obfsReferenceBin(t testing.TB, name string) string {
	t.Helper()
	bin := os.Getenv(name)
	if bin == "" {
		if os.Getenv("BIMERON_REQUIRE_SIMPLEOBFS_INTEROP") == "1" {
			t.Fatalf("%s is required", name)
		}
		t.Skip(name + " is not set")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatal(err)
	}
	return bin
}

func startObfsReference(t testing.TB, mode, backend string, custom bool) int {
	t.Helper()
	bin := obfsReferenceBin(t, "BIMERON_OBFS_SERVER_BIN")
	port := freePort(t)
	args := []string{"-s", "127.0.0.1", "-p", strconv.Itoa(port), "-r", backend, "--obfs", mode}
	if custom {
		args = append(args, "--obfs-host", "cover.example")
		if mode == "http" {
			args = append(args, "--http-method", "POST")
		}
	}
	startReference(t, bin, args...)
	waitReference(t, port)
	return port
}

func obfsReferenceProfile(t testing.TB, method, mode string, identity, custom bool) (accesskey.Profile, string) {
	t.Helper()
	obfsReferenceBin(t, "BIMERON_XRAY_BIN")
	secret := "test-only-simple-obfs"
	freshKey := func(size int) string {
		key := make([]byte, size)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(key)
	}
	if strings.HasPrefix(method, "2022-") {
		size := 32
		if method == "2022-blake3-aes-128-gcm" {
			size = 16
		}
		secret = freshKey(size)
	}
	settings := map[string]any{"method": method, "password": secret, "network": "tcp"}
	if identity {
		size := 32
		if method == "2022-blake3-aes-128-gcm" {
			size = 16
		}
		id := freshKey(size)
		settings["password"] = id
		settings["clients"] = []any{map[string]any{"password": secret, "email": "test-user"}}
		secret = id + ":" + secret
	}
	backend := testutil.StartXray(t, "shadowsocks", settings, nil)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	port := startObfsReference(t, mode, backend, custom)
	options := "obfs-local;obfs=" + mode
	if custom {
		options += ";obfs-host=cover.example"
		if mode == "http" {
			options += ";obfs-uri=/a%2Fb?q=x%2By;http-method=POST"
		}
	}
	p, err := accesskey.ParseSS("ss://" + base64.RawURLEncoding.EncodeToString([]byte(method+":"+secret)) + "@127.0.0.1:" + strconv.Itoa(port) + "/?plugin=" + url.QueryEscape(options))
	if err != nil {
		t.Fatal(err)
	}
	return p, echo.Addr().String()
}

func TestOriginalSimpleObfs(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		for _, mode := range []string{"http", "tls"} {
			for _, custom := range []bool{false, true} {
				if custom && os.Getenv("BIMERON_SIMPLEOBFS_RELEASE") == "1" {
					continue
				}
				t.Run(method+"/"+mode+"/custom="+strconv.FormatBool(custom), func(t *testing.T) {
					p, target := obfsReferenceProfile(t, method, mode, false, custom)
					c, err := New(p, net.Dialer{})
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					for range 2 {
						conn, err := c.DialStream(t.Context(), target)
						if err != nil {
							t.Fatal(err)
						}
						if err := roundTrip(conn, bytes.Repeat([]byte("obfs-transfer"), 18000)); err != nil {
							t.Fatal(err)
						}
						conn.Close()
					}
					c.mu.Lock()
					count := len(c.connections)
					c.mu.Unlock()
					if count != 0 {
						t.Fatal("closed connections were retained")
					}
				})
			}
		}
	}
}

func TestOriginalSimpleObfsIdentitiesAndConcurrency(t *testing.T) {
	for _, mode := range []string{"http", "tls"} {
		for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				p, target := obfsReferenceProfile(t, method, mode, true, false)
				c, err := New(p, net.Dialer{})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				var wg sync.WaitGroup
				for range 4 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						conn, err := c.DialStream(t.Context(), target)
						if err != nil {
							t.Error(err)
							return
						}
						defer conn.Close()
						if err := roundTrip(conn, bytes.Repeat([]byte("identity"), 20000)); err != nil {
							t.Error(err)
						}
					}()
				}
				wg.Wait()
			})
		}
	}
}

func TestOriginalSimpleObfsTransportOnly(t *testing.T) {
	for _, mode := range []string{"http", "tls"} {
		t.Run(mode, func(t *testing.T) {
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				for {
					c, err := echo.Accept()
					if err != nil {
						return
					}
					go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
				}
			}()
			port := startObfsReference(t, mode, echo.Addr().String(), false)
			raw, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			settings, _ := accesskey.ParseSSPlugin("obfs-local", "obfs="+mode)
			conn, err := simpleobfs.New(raw, *settings, port)
			if err != nil {
				t.Fatal(err)
			}
			if err := roundTrip(conn, bytes.Repeat([]byte("transport-only"), 100000)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOriginalSimpleObfsShutdownAndIndependentStreams(t *testing.T) {
	for _, mode := range []string{"http", "tls"} {
		t.Run(mode, func(t *testing.T) {
			p, target := obfsReferenceProfile(t, "aes-256-gcm", mode, false, false)
			c, err := New(p, net.Dialer{})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			first, err := c.DialStream(t.Context(), target)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second, err := c.DialStream(t.Context(), target)
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if err := roundTrip(first, []byte("first")); err != nil {
				t.Fatal(err)
			}
			first.CloseWrite() // Closing a direction closes only this plugin stream.
			if err := roundTrip(second, []byte("independent")); err != nil {
				t.Fatal(err)
			}
			c.Close()
			if _, err := second.Read(make([]byte, 1)); err == nil {
				t.Fatal("stream survived client close")
			}
			c.mu.Lock()
			count := len(c.connections)
			c.mu.Unlock()
			if count != 0 {
				t.Fatal("shutdown retained connections")
			}
		})
	}
}

func BenchmarkOriginalSimpleObfs(b *testing.B) {
	for _, mode := range []string{"http", "tls"} {
		b.Run(mode, func(b *testing.B) {
			p, target := obfsReferenceProfile(b, "aes-256-gcm", mode, false, false)
			c, err := New(p, net.Dialer{})
			if err != nil {
				b.Fatal(err)
			}
			defer c.Close()
			conn, err := c.DialStream(b.Context(), target)
			if err != nil {
				b.Fatal(err)
			}
			defer conn.Close()
			data := bytes.Repeat([]byte("benchmark-obfs"), 4096)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				if err := roundTrip(conn, data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
