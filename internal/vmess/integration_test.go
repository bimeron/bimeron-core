package vmess

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"bimeron/internal/accesskey"
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

func TestXrayVMessAEAD(t *testing.T) {
	bin := os.Getenv("BIMERON_XRAY_BIN")
	if bin == "" {
		t.Skip("set BIMERON_XRAY_BIN to run reference interoperability test")
	}
	cert, key, roots := testCertificate(t)
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
	for _, network := range []string{"tcp", "ws"} {
		for _, security := range []string{"aes-128-gcm", "chacha20-poly1305"} {
			for _, fingerprint := range []string{"", "chrome"} {
				t.Run(network+"/"+security+"/"+fingerprint, func(t *testing.T) {
					port := freePort(t)
					settings := `{"network":"tcp","security":"tls"}`
					if network == "ws" {
						settings = `{"network":"ws","security":"tls","wsSettings":{"path":"/vmess"}}`
					}
					config := fmt.Sprintf(`{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vmess","settings":{"clients":[{"id":%q,"alterId":0}]},"streamSettings":%s}],"outbounds":[{"protocol":"freedom"}]}`, port, id, settings)
					// Add the certificate through streamSettings without relying on a system trust store.
					config = string(bytes.Replace([]byte(config), []byte(`"security":"tls"`), []byte(fmt.Sprintf(`"security":"tls","tlsSettings":{"certificates":[{"certificateFile":%q,"keyFile":%q}]}`, cert, key)), 1))
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
					ready := false
					for i := 0; i < 100; i++ {
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
					v := accesskey.VMess{ID: id, Security: security, Network: network, TLS: "tls", ServerName: "localhost", Fingerprint: fingerprint}
					if network == "ws" {
						v.WSPath = "/vmess"
						v.ALPN = "http/1.1"
					}
					p := accesskey.Profile{Type: "vmess", TCP: accesskey.Endpoint{Host: "127.0.0.1", Port: port}, VMess: v}
					client, err := New(p, net.Dialer{})
					if err != nil {
						t.Fatal(err)
					}
					client.rootCAs = roots
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
				})
			}
		}
	}
}
