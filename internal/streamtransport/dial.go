package streamtransport

import (
	"context"
	"crypto/x509"
	"net"

	"bimeron/internal/accesskey"
	"bimeron/internal/shadowtls"
	"golang.getoutline.org/sdk/transport"
)

// Dial preserves the supplied socket controls and wraps the raw stream before
// the caller starts its inner protocol. roots applies to outer TLS verification;
// nil uses system trust. No connection without the wrapper is used on failure.
func Dial(ctx context.Context, dialer net.Dialer, address string, settings *accesskey.ShadowTLS, roots *x509.CertPool) (net.Conn, error) {
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil || settings == nil {
		return raw, err
	}
	return shadowtls.Client(ctx, raw, settings.ServerName, settings.Password, roots)
}

// Endpoint adapts the shared dialing path to Outline's existing endpoint API.
func Endpoint(address string, dialer net.Dialer, settings *accesskey.ShadowTLS, roots *x509.CertPool) transport.StreamEndpoint {
	return transport.FuncStreamEndpoint(func(ctx context.Context) (transport.StreamConn, error) {
		conn, err := Dial(ctx, dialer, address, settings, roots)
		if err != nil {
			return nil, err
		}
		// Dial produces either a TCPConn or a ShadowTLS Conn, both half-closeable.
		return conn.(transport.StreamConn), nil
	})
}
