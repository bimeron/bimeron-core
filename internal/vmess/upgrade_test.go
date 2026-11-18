package vmess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/streamtransport"
	"bimeron/internal/testutil"
)

func TestHTTPUpgradeDataAfterResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	payload := bytes.Repeat([]byte("data"), streamtransport.MaxUpgradeResponse/2)
	go func() {
		if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
			return
		}
		// One write puts data-phase bytes into the response read-ahead.
		_, _ = server.Write(append([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"), payload...))
	}()
	c := &Client{settings: accesskey.VMess{ServerName: "example.com", WSPath: "/"}}
	conn, err := c.httpUpgrade(client)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("data phase: %v", err)
	}
}

func TestUpgradeResponseLimit(t *testing.T) {
	for _, network := range []string{"ws", "httpupgrade"} {
		for name, chunk := range testutil.UpgradeChunks {
			t.Run(network+"/"+name, func(t *testing.T) {
				server, written := testutil.OversizedUpgradeServer(t, chunk)
				host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
				port, _ := strconv.Atoi(portText)
				c := &Client{endpoint: accesskey.Endpoint{Host: host, Port: port}, settings: accesskey.VMess{Network: network, TLS: "tls", ServerName: "127.0.0.1", WSPath: "/"}, rootCAs: x509.NewCertPool()}
				c.rootCAs.AddCert(server.Certificate())
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				conn, err := c.directTransport(ctx)
				if err == nil {
					conn.Close()
					t.Fatal("oversized response accepted")
				}
				if ctx.Err() != nil {
					t.Fatal("handshake did not stop reading")
				}
				if n := <-written; n > 8<<20 {
					t.Fatalf("server wrote %d response bytes", n)
				}
			})
		}
	}
}
