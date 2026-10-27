package quic

import (
	"fmt"

	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/wire"
)

// Frame count ranges follow uquic's Chrome 115/146 references (MIT).
// Serialize the original absolute CRYPTO offsets, including scattered ranges,
// so retransmissions and the second Initial never restart the TLS byte stream.
func (p *packetPacker) appendVersionedChromePayload(raw []byte, pl payload, padding protocol.ByteCount, v protocol.Version) ([]byte, error) {
	start := len(raw)
	expected := pl.length + padding
	if pl.ack != nil {
		var err error
		raw, err = pl.ack.Append(raw, v)
		if err != nil {
			return nil, err
		}
	}
	crypto, others := splitCryptoFrames(pl.frames)
	minCrypto, maxCrypto, minPing, maxPing, minPadding := 1, 10, 0, 10, 3
	if p.fingerprint == QUICChrome146 {
		minCrypto, maxCrypto, minPing, maxPing, minPadding = 6, 14, 1, 4, 2
	}
	target := minCrypto + p.rand.IntN(maxCrypto-minCrypto+1)
	for len(crypto) < target {
		var candidates []int
		for i, cf := range crypto {
			if len(cf.Data) > 1 {
				candidates = append(candidates, i)
			}
		}
		if len(candidates) == 0 {
			break
		}
		i := candidates[p.rand.IntN(len(candidates))]
		cf := crypto[i]
		cut := 1 + p.rand.IntN(len(cf.Data)-1)
		a := &wire.CryptoFrame{Offset: cf.Offset, Data: cf.Data[:cut]}
		b := &wire.CryptoFrame{Offset: cf.Offset + protocol.ByteCount(cut), Data: cf.Data[cut:]}
		cost := a.Length(v) + b.Length(v) - cf.Length(v)
		if padding < cost+protocol.ByteCount(maxPing+6) {
			break
		}
		padding -= cost
		crypto[i] = a
		crypto = append(crypto, b)
	}
	var items []chaosItem
	for _, cf := range crypto {
		items = append(items, chaosItem{frame: cf})
	}
	for _, f := range others {
		items = append(items, chaosItem{frame: f.Frame})
	}
	pings := min(protocol.ByteCount(minPing+p.rand.IntN(maxPing-minPing+1)), padding)
	for range pings {
		items = append(items, chaosItem{frame: &wire.PingFrame{}})
	}
	padding -= pings
	runs := min(protocol.ByteCount(minPadding+p.rand.IntN(7-minPadding)), padding)
	for left := runs; left > 0; left-- {
		n := padding
		if left > 1 {
			n = 1 + protocol.ByteCount(p.rand.IntN(int(padding-left+1)))
		}
		items = append(items, chaosItem{paddingLen: n})
		padding -= n
	}
	p.rand.Shuffle(len(items), func(i, j int) { items[i], items[j] = items[j], items[i] })
	for _, item := range items {
		if item.frame != nil {
			var err error
			raw, err = item.frame.Append(raw, v)
			if err != nil {
				return nil, err
			}
		} else {
			raw = append(raw, make([]byte, item.paddingLen)...)
		}
	}
	if protocol.ByteCount(len(raw)-start) != expected {
		return nil, fmt.Errorf("QUIC versioned Initial payload length mismatch")
	}
	return raw, nil
}
