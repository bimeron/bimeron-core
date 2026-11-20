//go:build ios && !cgo

package vpn

import (
	"crypto/tls"
	"errors"
)

func verifyDoHChain(tls.ConnectionState) error {
	return errors.New("iOS DoH requires a native Security.framework build")
}
