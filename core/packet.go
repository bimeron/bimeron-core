package core

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	tunstack "github.com/xjasonlyu/tun2socks/v2/core"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// PacketNetwork describes the host-provided path outside the VPN. The dialer
// MUST bypass captured routes; core never silently falls back to an OS backend.
type PacketNetwork struct {
	Identity string
	DNS      []string
	Dialer   net.Dialer
}

// PacketOptions delegates all network configuration to the embedding host.
// Outbound must honor ctx and change Identity when the physical path changes.
// Each engine/port pair is single-use; reconnect keeps the same port alive.
type PacketOptions struct {
	MTU      int
	Outbound func(context.Context) (PacketNetwork, error)
}

var ErrPacketPortClosed = errors.New("packet port closed")
var ErrInvalidPacket = errors.New("invalid IP packet")

// PacketPort exchanges raw IP packets, without Ethernet/utun family headers.
// Every crossing copies bytes; callers retain ownership of their input memory.
// The output queue is bounded to 256 packets. Saturation drops packets in the
// network stack rather than growing memory without limit.
type PacketPort struct {
	endpoint *channel.Endpoint
	mu       sync.RWMutex
	closed   bool
	used     atomic.Bool
	once     sync.Once
}

func NewPacketEngine(options Options, packetOptions PacketOptions) (*Engine, *PacketPort, error) {
	if packetOptions.MTU < 1280 || packetOptions.MTU > 1500 || packetOptions.Outbound == nil {
		return nil, nil, errors.New("packet backend requires MTU and outbound provider")
	}
	port := &PacketPort{endpoint: channel.New(256, uint32(packetOptions.MTU), "")}
	engine := New(options)
	engine.factory = func(c SessionConfig) backend {
		return &vpnBackend{platform: &packetPlatform{port: port, options: packetOptions, config: c}}
	}
	return engine, port, nil
}

func (p *PacketPort) WritePacket(packet []byte) error {
	if len(packet) < 20 || len(packet) > 65535 {
		return ErrInvalidPacket
	}
	protocol := header.IPv4ProtocolNumber
	switch packet[0] >> 4 {
	case 4:
		ihl := int(packet[0]&15) * 4
		if ihl < 20 || ihl > len(packet) || int(packet[2])<<8|int(packet[3]) != len(packet) {
			return ErrInvalidPacket
		}
	case 6:
		if len(packet) < 40 || (int(packet[4])<<8|int(packet[5]))+40 != len(packet) {
			return ErrInvalidPacket
		}
		protocol = header.IPv6ProtocolNumber
	default:
		return ErrInvalidPacket
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return ErrPacketPortClosed
	}
	if !p.endpoint.IsAttached() {
		return errors.New("packet port not ready")
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), packet...))})
	defer pkt.DecRef()
	p.endpoint.InjectInbound(protocol, pkt)
	return nil
}

func (p *PacketPort) ReadPacket(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pkt := p.endpoint.ReadContext(ctx)
	if pkt == nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, ErrPacketPortClosed
	}
	defer pkt.DecRef()
	view := pkt.ToView()
	defer view.Release()
	return append([]byte(nil), view.AsSlice()...), nil
}

// Close unblocks readers and rejects further writes. Stop the Engine as well.
func (p *PacketPort) Close() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.endpoint.Close()
		p.mu.Unlock()
	})
}

type packetPlatform struct {
	port    *PacketPort
	options PacketOptions
	config  SessionConfig
}

func (p *packetPlatform) Acquire(ctx context.Context) (func(), error) {
	if p.config.IKEv2 != nil {
		return nil, fault("ikev2_requires_native_host_backend", false)
	}
	if p.config.Mode != "vpn" || p.config.MTU != p.options.MTU {
		return nil, fault("invalid_packet_backend_config", false)
	}
	if p.config.KillSwitch {
		return nil, fault("packet_backend_kill_switch_requires_host_support", false)
	}
	if !p.port.used.CompareAndSwap(false, true) {
		return nil, fault("packet_backend_already_used", false)
	}
	return p.port.Close, nil
}
func (p *packetPlatform) Inspect(ctx context.Context, _ string, _ bool) (networkPath, error) {
	n, err := p.options.Outbound(ctx)
	if err != nil {
		return networkPath{}, fault("packet_outbound_unavailable", true)
	}
	return networkPath{identity: n.Identity, dns: append([]string(nil), n.DNS...), dialer: n.Dialer}, nil
}
func (p *packetPlatform) Open(_ context.Context, _ SessionConfig, router *flowRouter, report func(string, string)) (link, error) {
	s, err := tunstack.CreateStack(&tunstack.Config{LinkEndpoint: p.port.endpoint, TransportHandler: router})
	if err != nil {
		return nil, fault("packet_stack_failed", false)
	}
	report("packet_adapter_ready", "External IP packet adapter ready")
	return &packetLink{port: p.port, stack: s, router: router}, nil
}

type packetLink struct {
	port   *PacketPort
	stack  *stack.Stack
	router *flowRouter
}

func (l *packetLink) Close() error { l.port.Close(); l.stack.Close(); l.router.Close(); return nil }
