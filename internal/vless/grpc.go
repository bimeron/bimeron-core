package vless

import (
	"context"
	"net"
	"strconv"

	"bimeron/internal/streamtransport"
)

func (c *Client) grpcClient() (*streamtransport.GRPC, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if c.grpcTransport == nil {
		authority := c.settings.GRPCAuthority
		if authority == "" {
			authority = c.settings.ServerName
		}
		if authority == "" {
			authority = c.endpoint.Host
		}
		c.grpcTransport = streamtransport.NewGRPC(streamtransport.GRPCConfig{
			Address: net.JoinHostPort(c.endpoint.Host, strconv.Itoa(c.endpoint.Port)), Authority: authority,
			ServiceName: c.settings.GRPCServiceName, MultiMode: c.settings.GRPCMultiMode,
			DialContext: func(ctx context.Context, _ string) (net.Conn, error) { return c.DialSecure(ctx) },
		})
	}
	transport := c.grpcTransport
	c.mu.Unlock()
	return transport, nil
}

func (c *Client) grpcStream(ctx context.Context) (net.Conn, error) {
	transport, err := c.grpcClient()
	if err != nil {
		return nil, err
	}
	return transport.DialStream(ctx)
}
