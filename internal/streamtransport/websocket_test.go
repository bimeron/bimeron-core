package streamtransport

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"bimeron/internal/testutil"
)

func TestWebSocketDataAfterUpgrade(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	payload := bytes.Repeat([]byte("data"), MaxUpgradeResponse/2)
	go func() {
		request, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			return
		}
		sum := sha1.Sum([]byte(request.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		frame := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n\x82\x7f")
		frame = binary.BigEndian.AppendUint64(frame, uint64(len(payload)))
		// One write puts the first frame into the handshake read-ahead.
		_, _ = server.Write(append(frame, payload...))
	}()
	ws, err := WebSocket(client, "ws", "example.com", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(ws, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("data phase: %v", err)
	}
}

func TestWebSocketUpgradeResponseLimit(t *testing.T) {
	for name, chunk := range testutil.UpgradeChunks {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			written := make(chan int, 1)
			go func() { written <- testutil.OversizedUpgrade(server, chunk) }()
			done := make(chan error, 1)
			go func() {
				_, err := WebSocket(client, "ws", "example.com", "/", nil)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("oversized response accepted")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("handshake did not stop reading")
			}
			_ = client.Close()
			if n := <-written; n > MaxUpgradeResponse {
				t.Fatalf("read %d response bytes", n)
			}
		})
	}
}
