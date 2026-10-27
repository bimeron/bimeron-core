package streamtransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

// TLS connects a transport stream with certificate verification and optional
// browser ClientHello. Protocol framing remains with the caller.
func TLS(ctx context.Context, raw net.Conn, name string, protocols []string, fingerprint string, roots *x509.CertPool) (net.Conn, error) {
	if fingerprint == "" {
		conn := tls.Client(raw, &tls.Config{ServerName: name, NextProtos: protocols, MinVersion: tls.VersionTLS12, RootCAs: roots})
		if err := conn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return conn, nil
	}
	id, err := Fingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	conn := utls.UClient(raw, &utls.Config{ServerName: name, NextProtos: protocols, MinVersion: tls.VersionTLS12, RootCAs: roots}, id)
	if len(protocols) > 0 {
		if err := conn.BuildHandshakeState(); err != nil {
			return nil, fmt.Errorf("TLS client hello failed: %w", err)
		}
		found := false
		for _, extension := range conn.Extensions {
			if alpn, ok := extension.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = protocols
				found = true
			}
		}
		if !found {
			conn.Extensions = append(conn.Extensions, &utls.ALPNExtension{AlpnProtocols: protocols})
		}
		if err := conn.BuildHandshakeState(); err != nil {
			return nil, fmt.Errorf("TLS client hello failed: %w", err)
		}
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

func Fingerprint(name string) (utls.ClientHelloID, error) {
	switch name {
	case "chrome":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unsupported TLS fingerprint")
	}
}
