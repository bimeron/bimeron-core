//go:build windows || darwin

package vpn

import (
	"crypto/tls"
	"errors"
)

// The DoH transport alone uses this trust policy. Native verification must
// replace Go's default handshake verification before that verifier can fetch.
func dohTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // VerifyConnection performs complete offline verification.
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.ServerName == "" || len(state.PeerCertificates) == 0 {
				return errors.New("DoH TLS peer identity is missing")
			}
			if err := state.PeerCertificates[0].VerifyHostname(state.ServerName); err != nil {
				return err
			}
			return verifyDoHChain(state)
		},
	}
}
