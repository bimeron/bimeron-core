//go:build !windows && !darwin

package vpn

import "crypto/tls"

func dohTLSConfig() *tls.Config { return nil }
