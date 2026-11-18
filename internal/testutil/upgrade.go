package testutil

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// OversizedUpgrade answers an HTTP/1.1 upgrade with a 101 status line and then
// chunk(0), chunk(1), ... until a write fails or 64 MiB is sent. It drains conn
// concurrently so request writes cannot block, and returns bytes written.
func OversizedUpgrade(conn net.Conn, chunk func(int) string) int {
	go func() { _, _ = io.Copy(io.Discard, conn) }()
	n, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\n")
	for i := 0; err == nil && n < 64<<20; i++ {
		var m int
		m, err = io.WriteString(conn, chunk(i))
		n += m
	}
	return n
}

// UpgradeChunks are OversizedUpgrade chunks: one unterminated header line,
// and an unbounded run of distinct headers.
var UpgradeChunks = map[string]func(int) string{
	"line":    func(int) string { return strings.Repeat("a", 1024) },
	"headers": func(i int) string { return "X-Header-" + strconv.Itoa(i) + ": value\r\n" },
}

// OversizedUpgradeServer serves OversizedUpgrade over HTTP/1.1 TLS and reports
// bytes written per connection.
func OversizedUpgradeServer(t testing.TB, chunk func(int) string) (*httptest.Server, <-chan int) {
	written := make(chan int, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		written <- OversizedUpgrade(conn, chunk)
	}))
	t.Cleanup(server.Close)
	return server, written
}
