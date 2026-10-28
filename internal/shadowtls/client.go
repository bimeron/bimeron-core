// Package shadowtls implements the strict ShadowTLS v3 client wire protocol.
// Protocol reference: ihciah/shadow-tls v0.2.25, docs/protocol-v3-en.md.
// Application payload encryption remains the inner protocol's responsibility.
package shadowtls

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

var (
	ErrAuthentication = errors.New("ShadowTLS authentication failed")
	ErrRecord         = errors.New("invalid ShadowTLS record")
)

const (
	applicationData = 23
	tagSize         = 4
	maxRecord       = 16384 + 256 + tagSize
	maxPayload      = 16384 - tagSize
)

func newMAC(password string, initial ...[]byte) hash.Hash {
	h := hmac.New(sha1.New, []byte(password)) // Required by the v3 wire protocol.
	for _, data := range initial {
		_, _ = h.Write(data)
	}
	return h
}

// frameReader retains partial records across timeouts and never reads ahead of
// one record. The latter is essential when handing the socket back from TLS.
type frameReader struct {
	conn    net.Conn
	header  [5]byte
	headerN int
	body    []byte
	bodyN   int
}

func (r *frameReader) next() ([]byte, error) {
	if r.headerN < len(r.header) {
		n, err := io.ReadFull(r.conn, r.header[r.headerN:])
		r.headerN += n
		if err != nil {
			if errors.Is(err, io.EOF) && r.headerN > 0 {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
	if r.body == nil {
		size := int(binary.BigEndian.Uint16(r.header[3:]))
		if r.header[1] != 3 || (r.header[2] != 3 && r.header[2] != 1) || size == 0 || size > maxRecord {
			return nil, ErrRecord
		}
		r.body = make([]byte, size)
	}
	n, err := io.ReadFull(r.conn, r.body[r.bodyN:])
	r.bodyN += n
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	frame := append(r.header[:len(r.header):len(r.header)], r.body...)
	r.headerN, r.bodyN, r.body = 0, 0, nil
	return frame, nil
}

type handshakeConn struct {
	net.Conn
	reader     frameReader
	password   string
	pending    []byte
	random     []byte
	key        [32]byte
	mac        hash.Hash
	authorized bool
}

func (c *handshakeConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		frame, err := c.reader.next()
		if err != nil {
			return 0, err
		}
		if frame[0] == 22 && len(frame) >= 43 && frame[5] == 2 {
			if c.random != nil {
				return 0, ErrRecord
			} // No HelloRetryRequest transition.
			c.random = append([]byte(nil), frame[11:43]...)
			c.mac = newMAC(c.password, c.random)
			c.key = sha256.Sum256(append([]byte(c.password), c.random...))
		} else if frame[0] == applicationData {
			c.authorized = false
			if c.mac != nil && len(frame) > 5+tagSize {
				_, _ = c.mac.Write(frame[5+tagSize:])
				if hmac.Equal(c.mac.Sum(nil)[:tagSize], frame[5:5+tagSize]) {
					body := frame[5+tagSize:]
					for i := range body {
						body[i] ^= c.key[i%len(c.key)]
					}
					frame = append(frame[:5], body...)
					binary.BigEndian.PutUint16(frame[3:5], uint16(len(body)))
					c.authorized = true
				}
			}
		}
		c.pending = frame
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

// Client authenticates a raw TCP connection and takes ownership of it. roots
// may supply a private trust store; nil uses normal system certificate trust.
// Both the TLS target and ShadowTLS server must authenticate before any caller
// payload can be written. Setup cancellation does not cancel an established conn.
func Client(ctx context.Context, raw net.Conn, name, password string, roots *x509.CertPool) (*Conn, error) {
	if name == "" || password == "" || strings.ContainsAny(name, "\x00\r\n") {
		_ = raw.Close()
		return nil, ErrAuthentication
	}
	setup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	deadline, _ := setup.Deadline()
	_ = raw.SetDeadline(deadline)
	stop := context.AfterFunc(setup, func() { _ = raw.Close() })
	defer stop()
	ready := false
	defer func() {
		if !ready {
			_ = raw.Close()
		}
	}()
	wrapped := &handshakeConn{Conn: raw, reader: frameReader{conn: raw}, password: password}
	secure := utls.UClient(wrapped, &utls.Config{ServerName: name, RootCAs: roots,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}, utls.HelloChrome_Auto)
	if err := secure.BuildHandshakeState(); err != nil {
		return nil, ErrAuthentication
	}
	// HTTP/1.1 permits an ordinary cover request when a verified TLS peer fails
	// ShadowTLS authentication. This outer ALPN is unrelated to the inner ALPN.
	for _, extension := range secure.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
		if versions, ok := extension.(*utls.SupportedVersionsExtension); ok {
			versions.Versions = []uint16{tls.VersionTLS13}
		}
	}
	if err := secure.BuildHandshakeState(); err != nil {
		return nil, ErrAuthentication
	}
	hello := secure.HandshakeState.Hello
	if len(hello.Raw) < 71 || len(hello.SessionId) != 32 {
		return nil, ErrRecord
	}
	if _, err := rand.Read(hello.SessionId[:28]); err != nil {
		return nil, err
	}
	clear(hello.SessionId[28:])
	copy(hello.Raw[39:71], hello.SessionId)
	mac := newMAC(password, hello.Raw)
	copy(hello.SessionId[28:], mac.Sum(nil)[:tagSize])
	copy(hello.Raw[39:71], hello.SessionId)
	if err := secure.HandshakeContext(setup); err != nil {
		if setup.Err() != nil {
			return nil, setup.Err()
		}
		return nil, ErrAuthentication
	}
	if !wrapped.authorized || len(wrapped.random) != 32 || secure.ConnectionState().Version != tls.VersionTLS13 {
		coverDeadline := time.Now().Add(time.Second)
		if deadline.Before(coverDeadline) {
			coverDeadline = deadline
		}
		_ = raw.SetDeadline(coverDeadline)
		var noise [24]byte
		if _, err := rand.Read(noise[:]); err == nil {
			host := name
			if strings.Contains(host, ":") {
				host = "[" + host + "]"
			}
			_, _ = io.WriteString(secure, "GET / HTTP/1.1\r\nHost: "+host+"\r\nCookie: session="+base64.RawURLEncoding.EncodeToString(noise[:])+"\r\nConnection: close\r\n\r\n")
			_, _ = io.CopyN(io.Discard, secure, 4096)
		}
		return nil, ErrAuthentication
	}
	if len(wrapped.pending) != 0 {
		return nil, ErrRecord
	}
	if !stop() || setup.Err() != nil {
		if err := setup.Err(); err != nil {
			return nil, err
		}
		return nil, context.Canceled
	}
	_ = raw.SetDeadline(time.Time{})
	ready = true
	return &Conn{Conn: raw, reader: wrapped.reader, residual: wrapped.mac,
		readMAC: newMAC(password, wrapped.random, []byte("S")), writeMAC: newMAC(password, wrapped.random, []byte("C"))}, nil
}

// Conn carries authenticated v3 records. It does not encrypt caller payloads.
type Conn struct {
	net.Conn
	reader                      frameReader
	readMu, writeMu             sync.Mutex
	readMAC, writeMAC, residual hash.Hash
	pending                     []byte
	readErr, writeErr           error
	writeClosed                 bool
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.pending) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		frame, err := c.reader.next()
		if err != nil {
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				c.readErr = err
			}
			if c.readErr != nil && !errors.Is(err, io.EOF) {
				_ = c.Conn.Close()
			}
			return 0, err
		}
		if frame[0] != applicationData || frame[1] != 3 || frame[2] != 3 || len(frame) < 5+tagSize {
			c.readErr = ErrRecord
			_ = c.Conn.Close()
			return 0, c.readErr
		}
		body, tag := frame[5+tagSize:], frame[5:5+tagSize]
		if c.residual != nil {
			_, _ = c.residual.Write(body)
			if hmac.Equal(c.residual.Sum(nil)[:tagSize], tag) {
				continue
			}
			c.residual = nil
		}
		_, _ = c.readMAC.Write(body)
		if !hmac.Equal(c.readMAC.Sum(nil)[:tagSize], tag) {
			c.readErr = ErrAuthentication
			_ = c.Conn.Close()
			return 0, c.readErr
		}
		_, _ = c.readMAC.Write(tag)
		c.pending = body
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	written := 0
	for len(p) > 0 {
		body := p[:min(len(p), maxPayload)]
		_, _ = c.writeMAC.Write(body)
		tag := c.writeMAC.Sum(nil)[:tagSize]
		_, _ = c.writeMAC.Write(tag)
		frame := make([]byte, 5+tagSize+len(body))
		frame[0], frame[1], frame[2] = applicationData, 3, 3
		binary.BigEndian.PutUint16(frame[3:5], uint16(len(body)+tagSize))
		copy(frame[5:], tag)
		copy(frame[5+tagSize:], body)
		for len(frame) > 0 {
			n, err := c.Conn.Write(frame)
			if err == nil && n == 0 {
				err = io.ErrShortWrite
			}
			if err != nil {
				c.writeErr = err
				_ = c.Conn.Close() // The MAC chain cannot resume a partial record.
				return written, err
			}
			frame = frame[n:]
		}
		written += len(body)
		p = p[len(body):]
	}
	return written, nil
}

func (c *Conn) CloseRead() error {
	if half, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return half.CloseRead()
	}
	return c.Conn.Close()
}

func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return nil
	}
	c.writeClosed = true
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}
