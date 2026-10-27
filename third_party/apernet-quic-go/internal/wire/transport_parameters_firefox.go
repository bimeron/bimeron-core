// Firefox 116A transport parameter layout adapted from uquic (MIT).
package wire

import (
	"crypto/rand"
	"encoding/binary"
	"github.com/apernet/quic-go/quicvarint"
)

func (p *TransportParameters) marshalFirefox() []byte {
	var params [][]byte
	add := func(id transportParameterID, v uint64) { params = append(params, p.marshalVarintParam(nil, id, v)) }
	raw := func(id uint64, v []byte) {
		b := quicvarint.Append(nil, id)
		b = quicvarint.Append(b, uint64(len(v)))
		params = append(params, append(b, v...))
	}
	add(initialMaxStreamDataBidiRemoteParameterID, uint64(p.InitialMaxStreamDataBidiRemote))
	add(initialMaxStreamsBidiParameterID, uint64(p.MaxBidiStreamNum))
	add(maxDatagramFrameSizeParameterID, uint64(p.MaxDatagramFrameSize))
	add(maxIdleTimeoutParameterID, 30000)
	add(activeConnectionIDLimitParameterID, p.ActiveConnectionIDLimit)
	raw(0x2ab2, nil)
	v := binary.BigEndian.AppendUint32(nil, 1)
	v = binary.BigEndian.AppendUint32(v, greaseQUICVersion())
	v = binary.BigEndian.AppendUint32(v, 1)
	raw(0xff73db, v)
	add(initialMaxStreamsUniParameterID, uint64(p.MaxUniStreamNum))
	var g [2]byte
	rand.Read(g[:])
	raw(31*randUint64n((1<<62-1-27)/31)+27, g[:])
	add(initialMaxStreamDataBidiLocalParameterID, uint64(p.InitialMaxStreamDataBidiLocal))
	add(initialMaxStreamDataUniParameterID, uint64(p.InitialMaxStreamDataUni))
	raw(uint64(initialSourceConnectionIDParameterID), p.InitialSourceConnectionID.Bytes())
	add(maxAckDelayParameterID, 20)
	add(initialMaxDataParameterID, uint64(p.InitialMaxData))
	raw(uint64(disableActiveMigrationParameterID), nil)
	shuffleParams(params)
	var out []byte
	for _, b := range params {
		out = append(out, b...)
	}
	return out
}
