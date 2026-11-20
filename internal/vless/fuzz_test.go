package vless

import (
	"bytes"
	"testing"
)

// Response headers and XUDP frames come from the server.
func FuzzWire(f *testing.F) {
	f.Add([]byte{0, 0})
	// XUDP: a Keep frame with an IPv4 source, then a 3-byte payload.
	f.Add([]byte{0, 12, 0, 0, 2, 1, 2, 0, 80, 1, 127, 0, 0, 1, 0, 3, 'a', 'b', 'c'})
	// readAddress: port 80, IPv4.
	f.Add([]byte{0, 80, 1, 127, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = readResponseHeader(bytes.NewReader(b))
		_, _ = readAddress(b)
		r := bytes.NewReader(b)
		for i := 0; i < 64; i++ {
			d, err := xudpRead(r, nil)
			if err != nil {
				break
			}
			if len(d.data) == 0 || len(d.data) > maxPacket {
				t.Fatalf("XUDP payload of %d bytes", len(d.data))
			}
		}
	})
}
