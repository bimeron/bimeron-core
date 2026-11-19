package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// Listen opens a UDP socket on the session's outbound network path. It must
// apply the same interface binding, Android protect or host network as other
// upstream sockets so that tunnel datagrams never loop into Bimeron's TUN.
type Listen func(ctx context.Context, network, address string) (net.PacketConn, error)

// Bind is a single-socket conn.Bind for one fixed peer endpoint. Datagrams
// from other sources are dropped before they reach the engine.
type Bind struct {
	listen Listen
	peer   netip.AddrPort
	// port is a configured ListenPort; zero means ephemeral. Open always
	// binds it, whatever the engine requests, so a failed attempt can
	// never fall back to another port.
	port     uint16
	mu       sync.Mutex
	socket   *net.UDPConn
	sent     atomic.Uint64
	received atomic.Uint64
	// failed records the last Open result so start errors can tell socket
	// failures from invalid configuration.
	failed atomic.Bool
}

func (b *Bind) openFailed() bool { return b.failed.Load() }

var _ conn.Bind = (*Bind)(nil)

// NewBind returns a bind that reaches peer through listen from local port
// (zero for an ephemeral port).
func NewBind(listen Listen, peer netip.AddrPort, port uint16) *Bind {
	return &Bind{listen: listen, peer: netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()), port: port}
}

// errBind replaces socket errors, which may contain local addresses.
var errBind = errors.New("WireGuard socket failed")

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	if b.port != 0 {
		port = b.port
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	network, local := "udp4", "0.0.0.0"
	if b.peer.Addr().Is6() {
		network, local = "udp6", "::"
	}
	pc, err := b.listen(context.Background(), network, net.JoinHostPort(local, strconv.Itoa(int(port))))
	if err != nil {
		b.failed.Store(true)
		return nil, 0, errBind
	}
	socket, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		b.failed.Store(true)
		return nil, 0, errBind
	}
	b.failed.Store(false)
	b.socket = socket
	actual := uint16(0)
	if addr, ok := socket.LocalAddr().(*net.UDPAddr); ok {
		actual = uint16(addr.Port)
	}
	if b.port != 0 && actual != b.port {
		_ = socket.Close()
		b.socket = nil
		b.failed.Store(true)
		return nil, 0, errBind
	}
	return []conn.ReceiveFunc{b.receiver(socket)}, actual, nil
}

func (b *Bind) receiver(socket *net.UDPConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, from, err := socket.ReadFromUDPAddrPort(packets[0])
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return 0, net.ErrClosed
				}
				return 0, err
			}
			if netip.AddrPortFrom(from.Addr().Unmap(), from.Port()) != b.peer {
				continue
			}
			b.received.Add(uint64(n))
			sizes[0] = n
			eps[0] = endpoint(b.peer)
			return 1, nil
		}
	}
}

func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket == nil {
		return nil
	}
	err := b.socket.Close()
	b.socket = nil
	if err != nil {
		return errBind
	}
	return nil
}

// SetMark is a no-op: routing bypass comes from the outbound socket options.
func (b *Bind) SetMark(uint32) error { return nil }

func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	socket := b.socket
	b.mu.Unlock()
	if socket == nil {
		return net.ErrClosed
	}
	to := b.peer
	if e, ok := ep.(endpoint); ok {
		to = netip.AddrPort(e)
	}
	for _, buf := range bufs {
		if _, err := socket.WriteToUDPAddrPort(buf, to); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return net.ErrClosed
			}
			return errBind
		}
		b.sent.Add(uint64(len(buf)))
	}
	return nil
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, errors.New("invalid WireGuard endpoint")
	}
	return endpoint(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())), nil
}

func (b *Bind) BatchSize() int { return 1 }

// Traffic reports encrypted bytes sent and received on the wire.
func (b *Bind) Traffic() (sent, received uint64) { return b.sent.Load(), b.received.Load() }

type endpoint netip.AddrPort

func (e endpoint) ClearSrc()           {}
func (e endpoint) SrcToString() string { return "" }
func (e endpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e endpoint) DstToBytes() []byte {
	b, _ := netip.AddrPort(e).MarshalBinary()
	return b
}
func (e endpoint) DstIP() netip.Addr { return netip.AddrPort(e).Addr() }
func (e endpoint) SrcIP() netip.Addr { return netip.Addr{} }
