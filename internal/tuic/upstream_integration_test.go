package tuic

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

// Run with TUIC_SERVER_BIN pointing to the upstream tuic-server executable.
func TestUpstreamServer(t *testing.T) {
	bin := os.Getenv("TUIC_SERVER_BIN")
	if bin == "" {
		t.Skip("set TUIC_SERVER_BIN for reference-server interoperability")
	}
	cert, roots := testTLS(t)
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath, configPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "server.json")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	portSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := portSocket.LocalAddr().String()
	_ = portSocket.Close()
	config, _ := json.Marshal(map[string]any{
		"server": serverAddr, "users": map[string]string{"123e4567-e89b-12d3-a456-426614174000": "secret"},
		"certificate": certPath, "private_key": keyPath, "alpn": []string{"h3"}, "log_level": "info",
	})
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-c", configPath)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("reference server: %s", output.String())
		}
	}()

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	go func() {
		conn, err := tcpListener.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()
	udpServer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpServer.Close()
	go func() {
		var b [128]byte
		n, addr, err := udpServer.ReadFrom(b[:])
		if err == nil {
			_, _ = udpServer.WriteTo(b[:n], addr)
		}
	}()

	host, port, _ := net.SplitHostPort(serverAddr)
	profile, err := accesskey.ParseTUIC(fmt.Sprintf("tuic://123e4567-e89b-12d3-a456-426614174000:secret@%s:%s?sni=localhost&udp_relay_mode=quic", host, port))
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(profile, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	client.rootCAs = roots
	defer client.Close()
	var streamErr error
	var stream io.ReadWriteCloser
	readyDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(readyDeadline) {
		stream, streamErr = client.DialStream(ctx, tcpListener.Addr().String())
		if streamErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if streamErr != nil {
		t.Fatalf("TUIC TCP connect: %v", streamErr)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var got [4]byte
	if _, err := io.ReadFull(stream, got[:]); err != nil || string(got[:]) != "ping" {
		t.Fatalf("TUIC TCP: %q, %v", got, err)
	}
	packet, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	_ = packet.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := packet.WriteTo([]byte("dns"), udpServer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	var b [16]byte
	n, _, err := packet.ReadFrom(b[:])
	if err != nil || string(b[:n]) != "dns" {
		t.Fatalf("TUIC UDP: %q, %v", b[:n], err)
	}
}
