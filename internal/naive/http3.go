package naive

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// Each QUIC connection owns its UDP socket. Failed handshakes and terminated
// connections release it; Close also releases sockets while dialing is pending.
func (c *Client) quicDialer(dialer net.Dialer) func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, _ string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		stop := context.AfterFunc(c.ctx, cancel)
		defer stop()
		resolver := dialer.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		ips, err := resolver.LookupNetIP(ctx, "ip", c.profile.TCP.Host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("NaiveProxy endpoint resolution failed")
		}
		ip := ips[0].Unmap()
		for _, candidate := range ips {
			if candidate.Unmap().Is4() {
				ip = candidate.Unmap()
				break
			}
		}
		network, local := "udp4", "0.0.0.0:0"
		if ip.Is6() {
			network, local = "udp6", "[::]:0"
		}
		socket, err := (&net.ListenConfig{Control: dialer.Control}).ListenPacket(ctx, network, local)
		if err != nil {
			return nil, fmt.Errorf("NaiveProxy UDP socket failed")
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = socket.Close()
			return nil, net.ErrClosed
		}
		c.sockets[socket] = struct{}{}
		c.mu.Unlock()
		release := func() {
			_ = socket.Close()
			c.mu.Lock()
			delete(c.sockets, socket)
			c.mu.Unlock()
		}
		remote := &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: c.profile.TCP.Port, Zone: ip.Zone()}
		tlsConfig := &tls.Config{ServerName: c.profile.Naive.ServerName, RootCAs: c.rootCAs, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}
		// Dial waits for certificate verification and the full handshake. No 0-RTT.
		conn, err := quic.Dial(ctx, socket, remote, tlsConfig, cfg)
		if err != nil {
			release()
			return nil, fmt.Errorf("NaiveProxy QUIC handshake failed")
		}
		go func() {
			<-conn.Context().Done()
			release()
		}()
		return conn, nil
	}
}
