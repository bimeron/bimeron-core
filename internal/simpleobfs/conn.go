// Package simpleobfs implements the client wire transport for simple-obfs.
// TLS mode is obfuscation, not a cryptographic TLS session.
package simpleobfs

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"bimeron/internal/accesskey"
)

const maxRecord = 16384

type Conn struct {
	net.Conn
	settings          accesskey.SSPlugin
	port              int
	reader            *bufio.Reader
	readMu            sync.Mutex
	writeMu           sync.Mutex
	readInit          bool
	wrote             bool
	remaining         int
	readErr, writeErr error
}

// New wraps an already-connected stream. The first nonempty write starts the
// protocol; waiting for a response here would deadlock a TLS-mode server.
func New(raw net.Conn, settings accesskey.SSPlugin, port int) (*Conn, error) {
	if settings.Name != "obfs-local" || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid simple-obfs endpoint")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return &Conn{Conn: raw, settings: settings, port: port, reader: bufio.NewReader(raw)}, nil
}

// The original server closes both sockets when either peer sends EOF. Expose
// full-close semantics rather than promise a half-close it cannot preserve.
func (c *Conn) CloseRead() error  { return c.Close() }
func (c *Conn) CloseWrite() error { return c.Close() }

func (c *Conn) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	defer func() {
		if err != nil {
			c.readErr = err
			_ = c.Close()
		}
	}()
	if !c.readInit {
		if c.settings.Mode == "http" {
			err = c.readHTTPHeader()
		} else {
			err = c.readTLSHello()
		}
		if err != nil {
			return 0, err
		}
		c.readInit = true
	}
	if c.settings.Mode == "http" {
		return c.reader.Read(p)
	}
	for c.remaining == 0 {
		c.remaining, err = c.recordHeader(0x17, 0x0303)
		if err != nil {
			return 0, err
		}
	}
	n, err = c.reader.Read(p[:min(len(p), c.remaining)])
	c.remaining -= n
	if err == io.EOF && c.remaining != 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (c *Conn) readHTTPHeader() error {
	var header []byte
	for len(header) < 8192 {
		b, err := c.reader.ReadByte()
		if err != nil {
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		header = append(header, b)
		if len(header) >= 4 && string(header[len(header)-4:]) == "\r\n\r\n" {
			line, _, _ := strings.Cut(string(header), "\r\n")
			if line != "HTTP/1.1 101" && !strings.HasPrefix(line, "HTTP/1.1 101 ") {
				return fmt.Errorf("invalid simple-obfs HTTP response")
			}
			return nil
		}
	}
	return fmt.Errorf("simple-obfs HTTP response header too large")
}

func (c *Conn) recordHeader(kind byte, version uint16) (int, error) {
	var h [5]byte
	if _, err := io.ReadFull(c.reader, h[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(h[3:]))
	if h[0] != kind || binary.BigEndian.Uint16(h[1:3]) != version || n > maxRecord {
		return 0, fmt.Errorf("invalid simple-obfs TLS record")
	}
	return n, nil
}

func (c *Conn) readTLSHello() error {
	n, err := c.recordHeader(0x16, 0x0301)
	if err != nil {
		return err
	}
	if n != 91 {
		return fmt.Errorf("invalid simple-obfs ServerHello length")
	}
	var hello [91]byte
	if _, err := io.ReadFull(c.reader, hello[:]); err != nil {
		return err
	}
	if hello[0] != 2 || hello[1] != 0 || binary.BigEndian.Uint16(hello[2:4]) != 87 || binary.BigEndian.Uint16(hello[4:6]) != 0x0303 || hello[38] != 32 {
		return fmt.Errorf("invalid simple-obfs ServerHello")
	}
	n, err = c.recordHeader(0x14, 0x0303)
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("invalid simple-obfs ChangeCipherSpec")
	}
	b, err := c.reader.ReadByte()
	if err != nil {
		return err
	}
	if b != 1 {
		return fmt.Errorf("invalid simple-obfs ChangeCipherSpec")
	}
	c.remaining, err = c.recordHeader(0x16, 0x0303)
	return err
}

func (c *Conn) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	defer func() {
		if err != nil {
			c.writeErr = err
			_ = c.Close()
		}
	}()
	if c.settings.Mode == "http" {
		if !c.wrote {
			var key [16]byte
			if _, err = rand.Read(key[:]); err != nil {
				return 0, err
			}
			host := c.settings.Host
			if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
				host = "[" + host + "]"
			}
			if c.port != 80 {
				host += ":" + strconv.Itoa(c.port)
			}
			header := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/7.52.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nContent-Length: %d\r\n\r\n", c.settings.Method, c.settings.Path, host, base64.StdEncoding.EncodeToString(key[:]), len(p))
			if _, err = writeAll(c.Conn, []byte(header)); err != nil {
				return 0, err
			}
			c.wrote = true
		}
		return writeAll(c.Conn, p)
	}
	for len(p) > 0 {
		size := min(len(p), maxRecord)
		var frame []byte
		if !c.wrote {
			// Leave room for the complete ClientHello in upstream's 16 KiB
			// input buffer, including a maximum-length camouflage hostname.
			size = min(size, 8192)
			frame, err = c.clientHello(p[:size])
			if err != nil {
				return n, err
			}
		} else {
			frame = []byte{0x17, 3, 3}
			frame = binary.BigEndian.AppendUint16(frame, uint16(size))
			frame = append(frame, p[:size]...)
		}
		if _, err = writeAll(c.Conn, frame); err != nil {
			return n, err
		}
		c.wrote = true
		n += size
		p = p[size:]
	}
	return n, nil
}

func (c *Conn) clientHello(payload []byte) ([]byte, error) {
	// This layout is a wire requirement: the peer reads a fixed 138-byte
	// prefix followed immediately by the session-ticket extension.
	b := []byte{0x16, 3, 1, 0, 0, 1, 0, 0, 0, 3, 3}
	b = binary.BigEndian.AppendUint32(b, uint32(time.Now().Unix()))
	random := make([]byte, 60)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	b = append(b, random[:28]...)
	b = append(b, 32)
	b = append(b, random[28:]...)
	suites := []uint16{0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b, 0xc02f, 0x009e, 0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067, 0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff}
	b = binary.BigEndian.AppendUint16(b, uint16(len(suites)*2))
	for _, suite := range suites {
		b = binary.BigEndian.AppendUint16(b, suite)
	}
	b = append(b, 1, 0, 0, 0) // Null compression, followed by extension length.
	ext := extension(nil, 0x0023, payload)
	host := []byte{0}
	host = binary.BigEndian.AppendUint16(host, uint16(len(c.settings.Host)))
	host = append(host, c.settings.Host...)
	sni := binary.BigEndian.AppendUint16(nil, uint16(len(host)))
	sni = append(sni, host...)
	ext = extension(ext, 0, sni)
	ext = extension(ext, 11, []byte{3, 1, 0, 2})
	ext = extension(ext, 10, []byte{0, 8, 0, 29, 0, 23, 0, 25, 0, 24})
	sig := []byte{0, 30}
	for _, hash := range []byte{6, 5, 4, 3, 2} {
		for _, algorithm := range []byte{1, 2, 3} {
			sig = append(sig, hash, algorithm)
		}
	}
	ext = extension(ext, 13, sig)
	ext = extension(ext, 22, nil)
	ext = extension(ext, 23, nil)
	binary.BigEndian.PutUint16(b[len(b)-2:], uint16(len(ext)))
	b = append(b, ext...)
	binary.BigEndian.PutUint16(b[3:5], uint16(len(b)-5))
	binary.BigEndian.PutUint16(b[7:9], uint16(len(b)-9))
	return b, nil
}

func extension(dst []byte, kind uint16, body []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, kind)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(body)))
	return append(dst, body...)
}

func writeAll(w io.Writer, p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		written, err := w.Write(p)
		n += written
		p = p[written:]
		if err != nil {
			return n, err
		}
		if written == 0 {
			return n, io.ErrShortWrite
		}
	}
	return n, nil
}
