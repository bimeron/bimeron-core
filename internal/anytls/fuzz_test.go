package anytls

import (
	"bytes"
	"testing"
)

// Frames, UDP-over-TCP addresses and padding schemes come from the server.
func FuzzWire(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 1, 0, 3, 'a', 'b', 'c'})
	f.Add([]byte{2, 5, 'a', '.', 'c', 'o', 'm', 0, 80})
	f.Add([]byte(defaultPadding))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		for i := 0; i < 64; i++ {
			if _, _, _, err := readFrame(r); err != nil {
				break
			}
		}
		_, _ = readUoTAddress(bytes.NewReader(b))
		if s, err := parsePadding(string(b)); err == nil {
			for _, steps := range s.steps {
				for _, step := range steps {
					if n, err := padSize(step); err != nil || n < step.min || n > step.max {
						t.Fatalf("padding size %d outside %d-%d: %v", n, step.min, step.max, err)
					}
				}
			}
		}
	})
}
