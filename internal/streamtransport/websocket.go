package streamtransport

import (
	"encoding/base64"
	"fmt"
	"net"

	"golang.org/x/net/websocket"
)

// WebSocket performs an HTTP/1.1 upgrade over an already connected stream.
// TLS and setup deadlines belong to the caller. Early data is optional.
func WebSocket(conn net.Conn, scheme, host, path string, early []byte) (*websocket.Conn, error) {
	origin := "http"
	if scheme == "wss" {
		origin = "https"
	}
	config, err := websocket.NewConfig(scheme+"://"+host+path, origin+"://"+host)
	if err != nil {
		return nil, fmt.Errorf("invalid WebSocket settings")
	}
	if early != nil {
		config.Protocol = []string{base64.RawURLEncoding.EncodeToString(early)}
	}
	ws, err := websocket.NewClient(config, conn)
	if err != nil {
		return nil, fmt.Errorf("WebSocket handshake failed")
	}
	ws.PayloadType = websocket.BinaryFrame
	return ws, nil
}
