package masque

import (
	"fmt"
	"testing"

	"bimeron/internal/masque/masquetest"
)

// UDPEcho measures one round trip through the independent local reference proxy.
// SetBytes reports application payload bytes per round trip, excluding headers.
func BenchmarkUDPEcho(b *testing.B) {
	endpoints := masquetest.Start(b)
	for _, size := range []int{64, 512, 1200} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			c := fixtureClient(b, endpoints)
			p, err := c.ListenPacket(b.Context())
			if err != nil {
				b.Fatal(err)
			}
			defer p.Close()
			data := make([]byte, size)
			echo(b, p, endpoints["udp"], data)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				echo(b, p, endpoints["udp"], data)
			}
		})
	}
}
