package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"bimeron/internal/accesskey"
	"bimeron/internal/routing"
	"bimeron/internal/ss2022"
	"bimeron/internal/streamtransport"
	"bimeron/internal/telemetry"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
)

func Outline(e accesskey.Endpoint) (transport.StreamDialer, error) {
	return OutlineTCP(e, net.Dialer{Timeout: 15 * time.Second})
}
func OutlineTCP(e accesskey.Endpoint, dialer net.Dialer) (transport.StreamDialer, error) {
	return OutlineProfile(accesskey.Profile{TCP: e}, dialer)
}

// OutlineProfile preserves ShadowTLS wrapping without duplicating encryption.
func OutlineProfile(p accesskey.Profile, dialer net.Dialer) (transport.StreamDialer, error) {
	if err := p.ValidateShadowTLS(); err != nil {
		return nil, err
	}
	if p.SSPlugin != nil {
		return nil, fmt.Errorf("Shadowsocks plugin requires the embedded plugin client")
	}
	if p.ShadowTLS == nil && ss2022.IsMethod(p.TCP.Cipher) {
		return ss2022.New(p.TCP, dialer)
	}
	endpoint := streamtransport.Endpoint(net.JoinHostPort(p.TCP.Host, strconv.Itoa(p.TCP.Port)), dialer, p.ShadowTLS, nil)
	return OutlineStream(p.TCP, endpoint)
}

// OutlineStream preserves cipher and prefix behavior over a supplied transport.
func OutlineStream(e accesskey.Endpoint, endpoint transport.StreamEndpoint) (transport.StreamDialer, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	if ss2022.IsMethod(e.Cipher) {
		return ss2022.NewWithEndpoint(e, net.Dialer{}, endpoint)
	}
	key, err := shadowsocks.NewEncryptionKey(e.Cipher, e.Secret)
	if err != nil {
		return nil, fmt.Errorf("could not create encryption key")
	}
	d, err := shadowsocks.NewStreamDialer(endpoint, key)
	if err != nil {
		return nil, err
	}
	if !utf8.ValidString(e.Prefix) {
		return nil, fmt.Errorf("invalid prefix encoding")
	}
	var prefix []byte
	for _, r := range e.Prefix {
		if r > 255 {
			return nil, fmt.Errorf("prefix must contain byte-valued characters")
		}
		prefix = append(prefix, byte(r))
	}
	// Keep at least 16 random bytes of salt.
	if len(prefix) > key.SaltSize()-16 {
		return nil, fmt.Errorf("prefix too long for selected cipher")
	}
	if len(prefix) > 0 {
		d.SaltGenerator = shadowsocks.NewPrefixSaltGenerator(prefix)
	}
	return d, nil
}

type Server struct {
	Proxy  transport.StreamDialer
	Policy *routing.Policy
	Stats  *telemetry.Counters
}

// Serve owns the listener and closes every client on cancellation. Only loopback
// binding is supported because this initial SOCKS service has no authentication.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	defer l.Close()
	address, ok := l.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		return fmt.Errorf("SOCKS listener must use loopback")
	}
	if s.Proxy == nil {
		return fmt.Errorf("missing proxy transport")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	defer wg.Wait()
	// Ensure cancellation runs before waiting for handlers on an accept failure.
	defer cancel()
	slots := make(chan struct{}, 128)
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("SOCKS listener failed")
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); defer func() { <-slots }(); s.handle(ctx, c) }()
	}
}
func reply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

// finishReply gives a rejected client a bounded chance to read the answer
// before the connection closes, so the reply is not lost to a TCP reset.
func finishReply(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 512)
	for {
		if _, err := c.Read(buffer); err != nil {
			return
		}
	}
}
func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	anonymous := false
	for _, m := range methods {
		if m == 0 {
			anonymous = true
		}
	}
	if !anonymous {
		_, _ = c.Write([]byte{5, 255})
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(c, request[:]); err != nil || request[0] != 5 || request[2] != 0 {
		return
	}
	if request[1] != 1 {
		_ = reply(c, 7)
		finishReply(c)
		return
	} // TCP CONNECT only; no fake UDP success.
	host := ""
	switch request[3] {
	case 1, 4:
		n := 4
		if request[3] == 4 {
			n = 16
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(c, length[:]); err != nil || length[0] == 0 {
			return
		}
		b := make([]byte, int(length[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	default:
		_ = reply(c, 8)
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(c, portBytes[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		_ = reply(c, 1)
		return
	}
	action := routing.Proxy
	ip, _ := netip.ParseAddr(host)
	domain := ""
	if !ip.IsValid() {
		domain = host
	}
	if s.Policy != nil {
		action = s.Policy.Decide(ip, domain)
	}
	s.Stats.RouteDecided(action)
	if action == routing.Block {
		_ = reply(c, 2)
		finishReply(c)
		return
	}
	d := s.Proxy
	if action == routing.Direct {
		d = &transport.TCPDialer{Dialer: net.Dialer{Timeout: 15 * time.Second}}
	}
	s.Stats.AttemptTCP()
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	upstream, err := d.DialStream(dialCtx, net.JoinHostPort(host, strconv.Itoa(int(port))))
	cancel()
	if err != nil {
		s.Stats.FailTCP()
		_ = reply(c, 1)
		finishReply(c)
		return
	}
	s.Stats.EstablishTCP()
	defer s.Stats.EndTCP()
	defer upstream.Close()
	stopUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stopUpstream()
	if err := reply(c, 0); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	done := make(chan error, 1)
	go func() { _, err := s.Stats.CopyUp(upstream, c); _ = upstream.CloseWrite(); done <- err }()
	_, err = s.Stats.CopyDown(c, upstream)
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	if err != nil && !errors.Is(err, net.ErrClosed) {
		_ = c.Close()
		_ = upstream.Close()
	}
	select {
	case <-done:
	case <-ctx.Done():
		_ = c.Close()
		_ = upstream.Close()
		<-done
	case <-time.After(5 * time.Second):
		_ = c.Close()
		_ = upstream.Close()
		<-done
	}
}
