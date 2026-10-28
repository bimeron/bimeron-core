package simpleobfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

type memoryConn struct {
	input                 *bytes.Reader
	output                bytes.Buffer
	readLimit, writeLimit int
	failAfter             int
	zeroWrite, closed     bool
}

func (c *memoryConn) Read(p []byte) (int, error) {
	if c.readLimit > 0 {
		p = p[:min(len(p), c.readLimit)]
	}
	return c.input.Read(p)
}
func (c *memoryConn) Write(p []byte) (int, error) {
	if c.zeroWrite {
		return 0, nil
	}
	if c.writeLimit > 0 {
		p = p[:min(len(p), c.writeLimit)]
	}
	if c.failAfter > 0 {
		p = p[:min(len(p), c.failAfter-c.output.Len())]
		n, _ := c.output.Write(p)
		if c.output.Len() == c.failAfter {
			return n, io.ErrClosedPipe
		}
		return n, nil
	}
	return c.output.Write(p)
}
func (c *memoryConn) Close() error                     { c.closed = true; return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

func newTestConn(t *testing.T, raw net.Conn, mode string) *Conn {
	t.Helper()
	p, err := accesskey.ParseSSPlugin("obfs-local", "obfs="+mode)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(raw, *p, 8388)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func serverRecord(kind byte, version uint16, body []byte) []byte {
	b := []byte{kind, byte(version >> 8), byte(version)}
	b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
	return append(b, body...)
}

func serverHello(payload []byte) []byte {
	hello := make([]byte, 91)
	hello[0], hello[3], hello[4], hello[5], hello[38] = 2, 87, 3, 3, 32
	b := serverRecord(0x16, 0x0301, hello)
	b = append(b, serverRecord(0x14, 0x0303, []byte{1})...)
	return append(b, serverRecord(0x16, 0x0303, payload)...)
}

func TestReadFragmentedAndCoalesced(t *testing.T) {
	for _, mode := range []string{"http", "tls"} {
		for _, limit := range []int{1, 7, 0} {
			input := []byte("HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: arbitrary\r\n\r\nfirstsecond")
			if mode == "tls" {
				input = append(serverHello([]byte("first")), serverRecord(0x17, 0x0303, []byte("second"))...)
			}
			raw := &memoryConn{input: bytes.NewReader(input), readLimit: limit}
			c := newTestConn(t, raw, mode)
			got, err := io.ReadAll(c)
			if err != nil || string(got) != "firstsecond" {
				t.Fatalf("%s/fragment=%d: %q, %v", mode, limit, got, err)
			}
		}
	}
}

func TestEmptyInitialResponse(t *testing.T) {
	for _, mode := range []string{"http", "tls"} {
		input := []byte("HTTP/1.1 101 Switching Protocols\r\n\r\npayload")
		if mode == "tls" {
			input = append(serverHello(nil), serverRecord(0x17, 0x0303, []byte("payload"))...)
		}
		c := newTestConn(t, &memoryConn{input: bytes.NewReader(input), readLimit: 1}, mode)
		got, err := io.ReadAll(c)
		if err != nil || string(got) != "payload" {
			t.Fatalf("%s: %q, %v", mode, got, err)
		}
	}
}

func TestRejectMalformedResponses(t *testing.T) {
	badHello := serverHello([]byte("payload"))
	badHello[5] = 1
	badCCS := serverHello(nil)
	badCCS[101] = 2
	for _, tc := range []struct {
		mode string
		data []byte
	}{
		{"http", []byte("HTTP/1.1 200 OK\r\n\r\nsecret")},
		{"http", []byte("HTTP/1.1 101 Switching Protocols\r\n")},
		{"http", []byte("HTTP/1.1 101 Switching Protocols\r\n" + strings.Repeat("a", 8192))},
		{"tls", badHello}, {"tls", badCCS},
		{"tls", []byte{0x16, 3, 1, 0, 90}},
		{"tls", []byte{0x16, 3, 1, 0xff, 0xff}},
		{"tls", serverHello([]byte("payload"))[:105]},
		{"tls", append(serverHello(nil), []byte{0x17, 3, 3, 0x40, 1}...)},
		{"tls", append(serverHello(nil), []byte{0x17, 3, 3, 0, 3, 'a'}...)},
		{"tls", append(serverHello(nil), []byte{0x17, 3}...)},
		{"tls", append(serverHello(nil), serverRecord(0x16, 0x0303, []byte("bad"))...)},
	} {
		raw := &memoryConn{input: bytes.NewReader(tc.data), readLimit: 1}
		c := newTestConn(t, raw, tc.mode)
		if _, err := io.ReadAll(c); err == nil {
			t.Fatalf("accepted malformed %s response", tc.mode)
		}
		if !raw.closed {
			t.Fatal("malformed response did not close the socket")
		}
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("framing failure was not terminal")
		}
	}
}

func TestTLSHandshakeEOFIsTruncation(t *testing.T) {
	wire := serverHello([]byte("payload"))
	// EOF at a complete record boundary is still truncation until the entire
	// initial response (ServerHello, CCS, payload record) has been received.
	for _, cut := range []int{0, 5, 96, 102} {
		raw := &memoryConn{input: bytes.NewReader(wire[:cut])}
		c := newTestConn(t, raw, "tls")
		if _, err := io.ReadAll(c); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("EOF at handshake byte %d: %v", cut, err)
		}
	}
}

func TestHTTPWritesHeaderOnce(t *testing.T) {
	for _, port := range []int{80, 8388} {
		raw := &memoryConn{input: bytes.NewReader(nil), writeLimit: 3}
		c := newTestConn(t, raw, "http")
		c.port = port
		for _, payload := range []string{"first", "second"} {
			if n, err := c.Write([]byte(payload)); err != nil || n != len(payload) {
				t.Fatal(n, err)
			}
		}
		out := raw.output.String()
		header, payload, ok := strings.Cut(out, "\r\n\r\n")
		if !ok || payload != "firstsecond" || !strings.HasPrefix(header, "GET / HTTP/1.1\r\n") || !strings.Contains(header, "Content-Length: 5") {
			t.Fatal("incorrect HTTP stream")
		}
		host := "Host: cloudfront.net"
		if port != 80 {
			host += ":8388"
		}
		if !strings.Contains(header, host+"\r\n") {
			t.Fatal("incorrect Host port")
		}
	}
}

func TestTLSWritesSplitLargePayload(t *testing.T) {
	raw := &memoryConn{input: bytes.NewReader(nil), writeLimit: 3}
	c := newTestConn(t, raw, "tls")
	payload := bytes.Repeat([]byte("ciphertext"), 12000)
	if n, err := c.Write(payload); err != nil || n != len(payload) {
		t.Fatal(n, err)
	}
	if n, err := c.Write([]byte("tail")); err != nil || n != 4 {
		t.Fatal(n, err)
	}
	wire := raw.output.Bytes()
	firstLen := int(binary.BigEndian.Uint16(wire[3:5])) + 5
	if firstLen > maxRecord || int(binary.BigEndian.Uint16(wire[7:9])) != firstLen-9 || binary.BigEndian.Uint16(wire[138:140]) != 0x23 {
		t.Fatal("incorrect ClientHello layout")
	}
	ticketLen := int(binary.BigEndian.Uint16(wire[140:142]))
	got := append([]byte{}, wire[142:142+ticketLen]...)
	sni := wire[142+ticketLen : firstLen]
	if binary.BigEndian.Uint16(sni[:2]) != 0 || !bytes.Contains(sni, []byte("cloudfront.net")) {
		t.Fatal("missing SNI")
	}
	for rest := wire[firstLen:]; len(rest) > 0; {
		if len(rest) < 5 || !bytes.Equal(rest[:3], []byte{0x17, 3, 3}) {
			t.Fatal("invalid application record")
		}
		n := int(binary.BigEndian.Uint16(rest[3:5]))
		if n > maxRecord || len(rest) < 5+n {
			t.Fatal("oversized or incomplete record")
		}
		got = append(got, rest[5:5+n]...)
		rest = rest[5+n:]
	}
	if !bytes.Equal(got, append(payload, []byte("tail")...)) {
		t.Fatal("payload changed during framing")
	}
}

func TestWriteFailureIsTerminal(t *testing.T) {
	for _, mode := range []string{"http", "tls"} {
		raw := &memoryConn{input: bytes.NewReader(nil), zeroWrite: true}
		c := newTestConn(t, raw, mode)
		if n, err := c.Write([]byte("payload")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
			t.Fatal(n, err)
		}
		raw.zeroWrite = false
		if _, err := c.Write([]byte("retry")); err == nil || !raw.closed || raw.output.Len() != 0 {
			t.Fatal("failed write was replayed")
		}
	}
}

func TestPartialTLSRecordWriteFailure(t *testing.T) {
	raw := &memoryConn{input: bytes.NewReader(nil)}
	c := newTestConn(t, raw, "tls")
	first, err := c.clientHello(make([]byte, 8192))
	if err != nil {
		t.Fatal(err)
	}
	raw.failAfter = len(first) + 8
	n, err := c.Write(make([]byte, 40000))
	if n != 8192 || !errors.Is(err, io.ErrClosedPipe) || !raw.closed {
		t.Fatalf("partial record write: %d, %v, closed=%t", n, err, raw.closed)
	}
	if _, err := c.Write([]byte("retry")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("partial record failure was not terminal")
	}
}

func TestCloseInterruptsBlockedReadAndWrite(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		raw, peer := net.Pipe()
		c := newTestConn(t, raw, "tls")
		done := make(chan error, 1)
		go func() {
			if operation == "read" {
				_, err := c.Read(make([]byte, 1))
				done <- err
			} else {
				_, err := c.Write([]byte("payload"))
				done <- err
			}
		}()
		c.Close()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("blocked operation succeeded after close")
			}
		case <-time.After(time.Second):
			t.Fatal("close did not interrupt I/O")
		}
		peer.Close()
	}
}

func TestReadDeadlineInterruptsIncompleteHandshake(t *testing.T) {
	for _, mode := range []string{"http", "tls"} {
		raw, peer := net.Pipe()
		c := newTestConn(t, raw, mode)
		prefix := []byte("HTTP/1.1 101 Switching Protocols\r\n")
		if mode == "tls" {
			prefix = serverHello(nil)[:96]
		}
		written := make(chan struct{})
		go func() { _, _ = peer.Write(prefix); close(written) }()
		if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		_, err := c.Read(make([]byte, 1))
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("%s handshake deadline: %v", mode, err)
		}
		c.Close()
		peer.Close()
		<-written
	}
}
