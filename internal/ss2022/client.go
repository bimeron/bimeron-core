// Package ss2022 implements the single-user client specified by SIP022.
package ss2022

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"bimeron/internal/accesskey"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

const subkeyContext = "shadowsocks 2022 session subkey"

type Client struct {
	method     string
	key        []byte
	server     string
	dialer     net.Dialer
	endpoint   transport.StreamEndpoint
	streamOnly bool
}

func New(e accesskey.Endpoint, dialer net.Dialer) (*Client, error) {
	c, err := NewWithEndpoint(e, dialer, &transport.TCPEndpoint{Address: net.JoinHostPort(e.Host, strconv.Itoa(e.Port)), Dialer: dialer})
	if err == nil {
		c.streamOnly = false
	}
	return c, err
}

// NewWithEndpoint uses a custom stream endpoint without enabling native UDP.
func NewWithEndpoint(e accesskey.Endpoint, dialer net.Dialer, endpoint transport.StreamEndpoint) (*Client, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	if !IsMethod(e.Cipher) {
		return nil, fmt.Errorf("not a Shadowsocks 2022 method")
	}
	key, _ := base64.StdEncoding.Strict().DecodeString(e.Secret)
	if endpoint == nil {
		return nil, fmt.Errorf("missing Shadowsocks stream endpoint")
	}
	return &Client{method: e.Cipher, key: key, server: net.JoinHostPort(e.Host, strconv.Itoa(e.Port)), dialer: dialer, endpoint: endpoint, streamOnly: true}, nil
}

func IsMethod(method string) bool {
	switch method {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return true
	}
	return false
}

func (c *Client) aead(salt []byte) (cipher.AEAD, error) {
	key := make([]byte, len(c.key))
	blake3.DeriveKey(key, subkeyContext, append(append([]byte(nil), c.key...), salt...))
	if c.method == "2022-blake3-chacha20-poly1305" {
		return chacha20poly1305.New(key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func address(addr string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid target port")
	}
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append([]byte{1}, v4...)
		} else {
			b = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid target host")
		}
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

func parseAddress(b []byte) (net.Addr, int, error) {
	if len(b) < 1 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	var host string
	var n int
	switch b[0] {
	case 1:
		n = 5
		if len(b) < n+2 {
			return nil, 0, io.ErrUnexpectedEOF
		}
		host = net.IP(b[1:n]).String()
	case 4:
		n = 17
		if len(b) < n+2 {
			return nil, 0, io.ErrUnexpectedEOF
		}
		host = net.IP(b[1:n]).String()
	case 3:
		if len(b) < 2 {
			return nil, 0, io.ErrUnexpectedEOF
		}
		n = 2 + int(b[1])
		if len(b) < n+2 {
			return nil, 0, io.ErrUnexpectedEOF
		}
		host = string(b[2:n])
	default:
		return nil, 0, fmt.Errorf("invalid address type")
	}
	port := binary.BigEndian.Uint16(b[n:])
	if port == 0 {
		return nil, 0, fmt.Errorf("invalid port")
	}
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: int(port)}, n + 2, nil
	}
	return packetAddress(net.JoinHostPort(host, strconv.Itoa(int(port)))), n + 2, nil
}

type packetAddress string

func (a packetAddress) Network() string { return "udp" }
func (a packetAddress) String() string  { return string(a) }

func validTime(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	delta := time.Now().Unix() - int64(binary.BigEndian.Uint64(b))
	return delta >= -30 && delta <= 30
}

type stream struct {
	net.Conn
	method                string
	key                   []byte
	readAEAD, writeAEAD   cipher.AEAD
	readNonce, writeNonce [12]byte
	requestSalt           []byte
	readBuffer            []byte
	started               bool
}

var _ transport.StreamConn = (*stream)(nil)

func (c *Client) DialStream(ctx context.Context, target string) (transport.StreamConn, error) {
	addr, err := address(target)
	if err != nil {
		return nil, err
	}
	conn, err := c.endpoint.ConnectStream(ctx)
	if err != nil {
		return nil, err
	}
	s := &stream{Conn: conn, method: c.method, key: c.key}
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	s.requestSalt = make([]byte, len(c.key))
	if _, err = rand.Read(s.requestSalt); err != nil {
		return nil, err
	}
	s.writeAEAD, err = c.aead(s.requestSalt)
	if err != nil {
		return nil, err
	}
	// A nonempty random padding field is required when no initial payload is sent.
	var padSize [1]byte
	if _, err = rand.Read(padSize[:]); err != nil {
		return nil, err
	}
	padding := make([]byte, 1+int(padSize[0]))
	if _, err = rand.Read(padding); err != nil {
		return nil, err
	}
	header := append(addr, byte(len(padding)>>8), byte(len(padding)))
	header = append(header, padding...)
	fixed := make([]byte, 11)
	binary.BigEndian.PutUint64(fixed[1:], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(fixed[9:], uint16(len(header)))
	packet := append([]byte(nil), s.requestSalt...)
	packet = s.seal(packet, fixed)
	packet = s.seal(packet, header)
	err = writeAll(conn, packet)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func increment(n *[12]byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
}

func (s *stream) seal(dst, plain []byte) []byte {
	dst = s.writeAEAD.Seal(dst, s.writeNonce[:], plain, nil)
	increment(&s.writeNonce)
	return dst
}

func (s *stream) open(ciphertext []byte) ([]byte, error) {
	p, err := s.readAEAD.Open(nil, s.readNonce[:], ciphertext, nil)
	if err == nil {
		increment(&s.readNonce)
	}
	return p, err
}

func (s *stream) readChunk(n int) ([]byte, error) {
	b := make([]byte, n+s.readAEAD.Overhead())
	if _, err := io.ReadFull(s.Conn, b); err != nil {
		return nil, err
	}
	return s.open(b)
}

func (s *stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !s.started {
		salt := make([]byte, len(s.requestSalt))
		if _, err := io.ReadFull(s.Conn, salt); err != nil {
			return 0, err
		}
		var err error
		// The response uses its own salt and key.
		s.readAEAD, err = (&Client{method: s.method, key: s.key}).aead(salt)
		if err != nil {
			return 0, err
		}
		h, err := s.readChunk(1 + 8 + len(s.requestSalt) + 2)
		if err != nil {
			return 0, err
		}
		if h[0] != 1 || !validTime(h[1:9]) || subtle.ConstantTimeCompare(h[9:9+len(s.requestSalt)], s.requestSalt) != 1 {
			return 0, fmt.Errorf("invalid Shadowsocks 2022 response")
		}
		n := int(binary.BigEndian.Uint16(h[len(h)-2:]))
		s.readBuffer, err = s.readChunk(n)
		if err != nil {
			return 0, err
		}
		s.started = true
	}
	for len(s.readBuffer) == 0 {
		length, err := s.readChunk(2)
		if err != nil {
			return 0, err
		}
		s.readBuffer, err = s.readChunk(int(binary.BigEndian.Uint16(length)))
		if err != nil {
			return 0, err
		}
	}
	n := copy(p, s.readBuffer)
	s.readBuffer = s.readBuffer[n:]
	return n, nil
}

func (s *stream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), 65535)
		packet := s.seal(nil, binary.BigEndian.AppendUint16(nil, uint16(n)))
		packet = s.seal(packet, p[:n])
		if err := writeAll(s.Conn, packet); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (s *stream) CloseRead() error {
	if c, ok := s.Conn.(interface{ CloseRead() error }); ok {
		return c.CloseRead()
	}
	return nil
}
func (s *stream) CloseWrite() error {
	if c, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return s.Conn.Close()
}

func writeAll(c net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := c.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
