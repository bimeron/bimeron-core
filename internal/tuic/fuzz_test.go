package tuic

import (
	"bytes"
	"testing"
)

// Relayed UDP packets carry a server-supplied address.
func FuzzReadAddress(f *testing.F) {
	f.Add([]byte{0, 3, 'a', 'b', 'c', 0, 80})
	f.Add([]byte{1, 127, 0, 0, 1, 1, 187})
	f.Add([]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = readAddress(bytes.NewReader(b))
	})
}
