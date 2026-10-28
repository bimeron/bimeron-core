package trojan

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

// TestXrayTrojanInterop uses an independent Trojan server. Set BIMERON_XRAY_BIN to run it.
func TestXrayTrojanInterop(t *testing.T) {
	bin := os.Getenv("BIMERON_XRAY_BIN")
	if bin == "" {
		t.Skip("BIMERON_XRAY_BIN is not set")
	}
	for _, network := range []string{"tcp", "ws", "grpc", "grpc-multi"} {
		t.Run(network, func(t *testing.T) { testXrayTrojan(t, bin, network) })
	}
}

func testXrayTrojan(t *testing.T, bin, network string) {
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
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 64)
		for {
			n, addr, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(b[:n], addr)
		}
	}()

	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	portListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portListener.Addr().(*net.TCPAddr).Port
	_ = portListener.Close()
	config := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "trojan", "settings": map[string]any{"clients": []any{map[string]any{"password": "temporary-test-password"}}}, "streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": certPath, "keyFile": keyPath}}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
	settings := config["inbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	transportNetwork := network
	if network == "grpc-multi" {
		transportNetwork = "grpc"
	}
	settings["network"] = transportNetwork
	if transportNetwork == "ws" {
		settings["wsSettings"] = map[string]any{"path": "/trojan", "host": "front.example.com"}
	}
	if transportNetwork == "grpc" {
		settings["grpcSettings"] = map[string]any{"serviceName": "trojan"}
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "-config", configPath)
	output, err := os.Create(filepath.Join(dir, "xray.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	root := x509.NewCertPool()
	root.AppendCertsFromPEM(certPEM)
	client, err := New(accesskey.Profile{Type: "trojan", TCP: accesskey.Endpoint{Host: "127.0.0.1", Port: port}, Trojan: accesskey.Trojan{Password: "temporary-test-password", ServerName: "localhost", Network: transportNetwork, WSPath: wsSetting(transportNetwork, "/trojan"), WSHost: wsSetting(transportNetwork, "front.example.com"), GRPCServiceName: grpcSetting(transportNetwork, "trojan"), GRPCAuthority: grpcSetting(transportNetwork, "front.example.com"), GRPCMultiMode: network == "grpc-multi"}}, net.Dialer{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client.rootCAs = root
	defer client.Close()
	for i := 0; i < 30; i++ {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{ServerName: "localhost", RootCAs: root})
		if err == nil {
			_ = c.Close()
			break
		}
		if i == 29 {
			t.Fatalf("Xray did not start: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	stream, err := client.DialStream(context.Background(), tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(stream, b); err != nil || string(b) != "ping" {
		t.Fatalf("TCP reply %q: %v", b, err)
	}
	_ = stream.Close()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			connection, err := client.DialStream(context.Background(), tcp.Addr().String())
			if err != nil {
				t.Error(err)
				return
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte(fmt.Sprintf("session-%d-", i)), 16384)
			done := make(chan error, 1)
			go func() { done <- writeAll(connection, payload) }()
			reply := make([]byte, len(payload))
			_, err = io.ReadFull(connection, reply)
			if err != nil || !bytes.Equal(reply, payload) {
				t.Errorf("large TCP transfer: %v", err)
			}
			if err := <-done; err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	packet, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	_ = packet.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := packet.WriteTo([]byte("pong"), trojanAddr(udp.LocalAddr().String())); err != nil {
		t.Fatal(err)
	}
	n, _, err := packet.ReadFrom(b)
	if err != nil || string(b[:n]) != "pong" {
		t.Fatalf("UDP reply %q: %v", b[:n], err)
	}
	if transportNetwork == "ws" || transportNetwork == "grpc" {
		t.Run("reject-wrong-route", func(t *testing.T) {
			settings := client.settings
			if transportNetwork == "ws" {
				settings.WSPath = "/wrong"
			} else {
				settings.GRPCServiceName = "wrong"
			}
			bad, err := New(accesskey.Profile{Type: "trojan", TCP: client.endpoint, Trojan: settings}, net.Dialer{})
			if err != nil {
				t.Fatal(err)
			}
			defer bad.Close()
			bad.rootCAs = root
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			connection, err := bad.DialStream(ctx, tcp.Addr().String())
			if err == nil {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(time.Second))
				_, err = connection.Write([]byte("ping"))
				if err == nil {
					_, err = io.ReadFull(connection, make([]byte, 4))
				}
			}
			if err == nil {
				t.Fatal("wrong route accepted")
			}
		})
	}
	_ = client.Close()
	if _, err := client.DialStream(t.Context(), tcp.Addr().String()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial after close: %v", err)
	}
	if _, err := packet.WriteTo([]byte("closed"), trojanAddr(udp.LocalAddr().String())); err == nil {
		t.Fatal("packet survived client close")
	}
}

func wsSetting(network, value string) string {
	if network == "ws" {
		return value
	}
	return ""
}
func grpcSetting(network, value string) string {
	if network == "grpc" {
		return value
	}
	return ""
}
