package core

import (
	"bimeron/internal/accesskey"
	"context"
	"crypto/tls"
	"net"
	"net/http"
)

// ResolveSSConf fetches validated configuration on the supplied physical path.
func ResolveSSConf(ctx context.Context, source string, network PacketNetwork) ([]byte, error) {
	return resolveSSConf(ctx, source, network, nil)
}

func resolveSSConf(ctx context.Context, source string, network PacketNetwork, tlsConfig *tls.Config) ([]byte, error) {
	d := bootstrapDialer(networkPath{dialer: network.Dialer, dns: network.DNS}, nil)
	t := &http.Transport{TLSClientConfig: tlsConfig, MaxResponseHeaderBytes: accesskey.MaxSSConfResponseHeaderBytes, DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp4", address)
	}}
	defer t.CloseIdleConnections()
	b, _, err := accesskey.NewResolverWithTransport(t).FetchSSConf(ctx, source)
	return b, err
}
