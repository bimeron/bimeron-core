package streamtransport

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"

	"bimeron/internal/captiveportal"
	"golang.org/x/net/websocket"
)

// MaxUpgradeResponse bounds bytes read during an HTTP/1.1 upgrade, including
// read-ahead into the data phase (4 KiB for the WebSocket client). Real
// responses are a few hundred bytes; 64 KiB admits large proxy headers while
// keeping parser state per handshake near 1 MiB.
const MaxUpgradeResponse = 64 << 10

var errUpgradeResponse = errors.New("HTTP upgrade response too large")

// UpgradeConn limits reads to MaxUpgradeResponse until Release. HTTP response
// parsers otherwise accumulate unterminated lines and headers without bound.
// Reads before Release must come from one goroutine.
type UpgradeConn struct {
	net.Conn
	left     int
	released atomic.Bool
	status   *[12]byte
	read     int
}

func NewUpgradeConn(conn net.Conn) *UpgradeConn {
	return &UpgradeConn{Conn: conn, left: MaxUpgradeResponse}
}

func (c *UpgradeConn) Read(b []byte) (int, error) {
	if c.released.Load() {
		return c.Conn.Read(b)
	}
	if c.left <= 0 {
		return 0, errUpgradeResponse
	}
	n, err := c.Conn.Read(b[:min(len(b), c.left)])
	c.left -= n
	if c.status != nil && c.read < len(c.status) {
		c.read += copy(c.status[c.read:], b[:n])
	}
	return n, err
}

// Release removes the limit for the data phase.
func (c *UpgradeConn) Release() { c.released.Store(true) }

// WebSocket performs an HTTP/1.1 upgrade over an already connected stream.
// TLS and setup deadlines belong to the caller. Early data is optional.
func WebSocket(ctx context.Context, conn net.Conn, scheme, host, path string, early []byte) (*websocket.Conn, error) {
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
	// The client keeps reading through limited after the handshake.
	limited := NewUpgradeConn(conn)
	if captiveportal.Observing(ctx) {
		limited.status = new([12]byte)
	}
	ws, err := websocket.NewClient(config, limited)
	if err != nil {
		if limited.status != nil {
			status := string(limited.status[:])
			code, _ := strconv.Atoi(status[9:])
			redirect := strings.HasPrefix(status, "HTTP/1.") && status[8] == ' ' && captiveportal.RedirectStatus(code)
			captiveportal.Failed(ctx, conn.RemoteAddr().String(), redirect)
		}
		return nil, fmt.Errorf("WebSocket handshake failed")
	}
	limited.Release()
	ws.PayloadType = websocket.BinaryFrame
	return ws, nil
}
