package proxy

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"
)

// SOCKS5 requests come from local clients and UDP replies from upstreams.
func FuzzReadSocksAddress(f *testing.F) {
	f.Add(byte(1), []byte{127, 0, 0, 1, 0, 80})
	f.Add(byte(3), []byte{3, 'a', 'b', 'c', 0, 80})
	f.Add(byte(4), make([]byte, 18))
	f.Fuzz(func(t *testing.T, atyp byte, b []byte) {
		address, err := readSocksAddress(bytes.NewReader(b), atyp)
		if err != nil {
			return
		}
		// A domain may hold any byte, including brackets that SplitHostPort
		// refuses, so check only the port after the last colon.
		i := strings.LastIndexByte(address, ':')
		if i < 0 {
			t.Fatalf("address %q has no port", address)
		}
		if n, err := strconv.Atoi(address[i+1:]); err != nil || n < 0 || n > 65535 {
			t.Fatalf("invalid port in %q", address)
		}
		if atyp != 3 {
			if _, _, err := net.SplitHostPort(address); err != nil {
				t.Fatalf("unparseable IP address %q: %v", address, err)
			}
		}
	})
}
