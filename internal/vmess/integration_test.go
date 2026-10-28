package vmess

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/vless"
	"golang.getoutline.org/sdk/transport"
)

func testCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certPath, cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, private, 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	return certPath, keyPath, roots
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

func TestXrayVMessAEAD(t *testing.T) { testXrayProtocol(t, "vmess") }

// Share server fixtures so both clients are checked against identical transports.
func TestXrayVLESSGRPC(t *testing.T) { testXrayProtocol(t, "vless") }

func testXrayProtocol(t *testing.T, protocol string) {
	bin := os.Getenv("BIMERON_XRAY_BIN")
	if bin == "" {
		t.Skip("set BIMERON_XRAY_BIN to run reference interoperability test")
	}
	cert, key, roots := testCertificate(t)
	decoyCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	decoy, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{decoyCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer decoy.Close()
	go func() {
		for {
			conn, err := decoy.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(io.Discard, conn) }()
		}
	}()
	realityKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	realityPublic := base64.RawURLEncoding.EncodeToString(realityKey.PublicKey().Bytes())
	realityPrivate := base64.RawURLEncoding.EncodeToString(realityKey.Bytes())
	const id = "123e4567-e89b-12d3-a456-426614174000"
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	udpListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpListener.Close()
	go func() {
		b := make([]byte, 8192)
		for {
			n, addr, err := udpListener.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = udpListener.WriteTo(b[:n], addr)
		}
	}()
	for _, scenario := range []struct{ network, mode, alpn string }{{"tcp", "", ""}, {"ws", "", ""}, {"httpupgrade", "", ""}, {"grpc", "", ""}, {"grpc", "multi", ""}, {"xhttp", "packet-up", ""}, {"xhttp", "stream-up", ""}, {"xhttp", "stream-one", ""}, {"xhttp", "auto", ""}, {"xhttp", "packet-up", "h3"}, {"xhttp", "stream-up", "h3"}, {"xhttp", "stream-one", "h3"}, {"xhttp", "auto", "h3"}} {
		network, mode := scenario.network, scenario.mode
		if protocol == "vless" && network != "grpc" {
			continue
		}
		fingerprints := []string{"", "chrome"}
		if scenario.alpn == "h3" {
			fingerprints = []string{""}
		}
		for _, transportSecurity := range []string{"tls", "reality"} {
			if transportSecurity == "reality" {
				if network != "tcp" && network != "grpc" && network != "xhttp" || scenario.alpn == "h3" || (network == "xhttp" && mode == "packet-up") {
					continue
				}
				fingerprints = []string{"chrome"}
			}
			for _, security := range []string{"aes-128-gcm", "chacha20-poly1305"} {
				if protocol == "vless" && security != "aes-128-gcm" {
					continue
				}
				for _, fingerprint := range fingerprints {
					t.Run(network+"/"+mode+"/"+scenario.alpn+"/"+transportSecurity+"/"+security+"/"+fingerprint, func(t *testing.T) {
						port := freePort(t)
						if scenario.alpn == "h3" {
							port = freeUDPPort(t)
						}
						settings := `{"network":"tcp","security":"tls"}`
						if network == "ws" {
							settings = `{"network":"ws","security":"tls","wsSettings":{"path":"/vmess"}}`
						} else if network == "httpupgrade" {
							settings = `{"network":"httpupgrade","security":"tls","httpupgradeSettings":{"path":"/vmess"}}`
						} else if network == "grpc" {
							settings = `{"network":"grpc","security":"tls","grpcSettings":{"serviceName":"vmess"}}`
							if mode == "multi" {
								settings = `{"network":"grpc","security":"tls","grpcSettings":{"serviceName":"vmess","multiMode":true}}`
							}
						} else if network == "xhttp" {
							settings = fmt.Sprintf(`{"network":"xhttp","security":"tls","xhttpSettings":{"path":"/vmess","mode":%q}}`, mode)
						}
						config := fmt.Sprintf(`{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vmess","settings":{"clients":[{"id":%q,"alterId":0}]},"streamSettings":%s}],"outbounds":[{"protocol":"freedom"}]}`, port, id, settings)
						if protocol == "vless" {
							config = strings.Replace(config, `"protocol":"vmess"`, `"protocol":"vless"`, 1)
							config = strings.Replace(config, `"settings":{"clients":`, `"settings":{"decryption":"none","clients":`, 1)
						}
						// Add the certificate through streamSettings without relying on a system trust store.
						tlsOptions := fmt.Sprintf(`"security":"tls","tlsSettings":{"certificates":[{"certificateFile":%q,"keyFile":%q}]}`, cert, key)
						if scenario.alpn == "h3" {
							tlsOptions = fmt.Sprintf(`"security":"tls","tlsSettings":{"alpn":["h3"],"certificates":[{"certificateFile":%q,"keyFile":%q}]}`, cert, key)
						}
						if transportSecurity == "reality" {
							tlsOptions = fmt.Sprintf(`"security":"reality","realitySettings":{"dest":%q,"serverNames":["localhost"],"privateKey":%q,"shortIds":["abcd"]}`, decoy.Addr().String(), realityPrivate)
						}
						config = string(bytes.Replace([]byte(config), []byte(`"security":"tls"`), []byte(tlsOptions), 1))
						configPath := filepath.Join(t.TempDir(), "xray.json")
						if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
							t.Fatal(err)
						}
						cmd := exec.Command(bin, "run", "-config", configPath)
						var logs bytes.Buffer
						cmd.Stdout = &logs
						cmd.Stderr = &logs
						if err := cmd.Start(); err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
						ready := scenario.alpn == "h3"
						if ready {
							time.Sleep(300 * time.Millisecond)
						}
						for i := 0; !ready && i < 100; i++ {
							conn, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
							if e == nil {
								conn.Close()
								ready = true
								break
							}
							time.Sleep(50 * time.Millisecond)
						}
						if !ready {
							t.Fatalf("Xray did not start: %s", logs.String())
						}
						v := accesskey.VMess{ID: id, Security: security, Network: network, TLS: transportSecurity, ServerName: "localhost", Fingerprint: fingerprint}
						if transportSecurity == "reality" {
							v.PublicKey, v.ShortID = realityPublic, "abcd"
						}
						if network == "ws" || network == "httpupgrade" {
							v.WSPath = "/vmess"
							v.ALPN = "http/1.1"
						} else if network == "grpc" {
							v.GRPCServiceName = "vmess"
							v.GRPCMultiMode = mode == "multi"
							v.ALPN = "h2"
						} else if network == "xhttp" {
							v.XHTTPPath, v.XHTTPMode = "/vmess", mode
							v.ALPN = "h2"
							if mode == "stream-up" && scenario.alpn == "" && transportSecurity == "tls" {
								v.XHTTPOptions = &accesskey.XHTTPOptions{Headers: map[string]string{"X-Test": "value"}}
							}
							if scenario.alpn == "h3" {
								v.ALPN = "h3"
							}
						}
						p := accesskey.Profile{Type: "vmess", TCP: accesskey.Endpoint{Host: "127.0.0.1", Port: port}, VMess: v}
						var client interface {
							DialStream(context.Context, string) (transport.StreamConn, error)
							ListenPacket(context.Context) (net.PacketConn, error)
							Close() error
						}
						if protocol == "vless" {
							vc, err := vless.New(accesskey.Profile{Type: "vless", TCP: p.TCP, VLESS: accesskey.VLESS{ID: id, Encryption: "none", Network: "grpc", Security: transportSecurity, ServerName: v.ServerName, Fingerprint: v.Fingerprint, PublicKey: v.PublicKey, ShortID: v.ShortID, ALPN: v.ALPN, GRPCServiceName: v.GRPCServiceName, GRPCMultiMode: v.GRPCMultiMode}}, net.Dialer{})
							if err != nil {
								t.Fatal(err)
							}
							vc.SetRootCAs(roots)
							client = vc
						} else {
							vc, err := New(p, net.Dialer{})
							if err != nil {
								t.Fatal(err)
							}
							vc.rootCAs = roots
							client = vc
						}
						defer client.Close()
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						stream, err := client.DialStream(ctx, tcpListener.Addr().String())
						if err != nil {
							t.Fatalf("VMess TCP dial: %v; Xray: %s", err, logs.String())
						}
						defer stream.Close()
						stream.SetDeadline(time.Now().Add(5 * time.Second))
						if _, err := stream.Write([]byte("hello")); err != nil {
							t.Fatal(err)
						}
						var echo [5]byte
						if _, err := io.ReadFull(stream, echo[:]); err != nil || string(echo[:]) != "hello" {
							t.Fatalf("VMess TCP echo: %q, %v; Xray: %s", echo, err, logs.String())
						}
						packet, err := client.ListenPacket(ctx)
						if err != nil {
							t.Fatal(err)
						}
						defer packet.Close()
						packet.SetDeadline(time.Now().Add(5 * time.Second))
						if _, err := packet.WriteTo([]byte("dns"), udpListener.LocalAddr()); err != nil {
							t.Fatalf("VMess UDP write: %v", err)
						}
						var udpEcho [8]byte
						n, _, err := packet.ReadFrom(udpEcho[:])
						if err != nil || string(udpEcho[:n]) != "dns" {
							t.Fatalf("VMess UDP echo: %q, %v; Xray: %s", udpEcho[:n], err, logs.String())
						}
						_ = stream.Close()
						reopened, err := client.DialStream(ctx, tcpListener.Addr().String())
						if err != nil {
							t.Fatalf("VMess reconnect: %v; Xray: %s", err, logs.String())
						}
						reopened.SetDeadline(time.Now().Add(5 * time.Second))
						if _, err := reopened.Write([]byte("again")); err != nil {
							t.Fatal(err)
						}
						if _, err := io.ReadFull(reopened, echo[:]); err != nil || string(echo[:]) != "again" {
							t.Fatalf("VMess reconnect echo: %q, %v; Xray: %s", echo, err, logs.String())
						}
						_ = reopened.Close()
						_ = packet.Close()
						_ = client.Close()
						if _, err := client.DialStream(ctx, tcpListener.Addr().String()); !errors.Is(err, net.ErrClosed) {
							t.Fatalf("VMess dial after close: %v", err)
						}
					})
				}
			}
		}
	}
}
