//go:build darwin && (!ios || cgo)

package vpn

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestDoHNativeTrust(t *testing.T) {
	testDoHTrust(t, func(root *x509.Certificate) func(tls.ConnectionState) error {
		return func(state tls.ConnectionState) error { return verifyAppleDoHChain(state, root) }
	})
}
