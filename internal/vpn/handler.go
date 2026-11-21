package vpn

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"sync"
	"time"

	"bimeron/internal/guard"
	"bimeron/internal/relay"
	"bimeron/internal/routing"
	"bimeron/internal/telemetry"

	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"golang.getoutline.org/sdk/transport"
)

const DNSAddress = "198.18.0.2"

// Handler turns netstack flows into upstream proxy or interface-bound direct sockets.
type Handler struct {
	TCP         transport.StreamDialer
	UDP         transport.PacketListener
	DirectTCP   transport.StreamDialer
	DirectUDP   transport.PacketDialer
	Policy      *routing.Policy
	Metadata    *DNSMetadata
	DisableIPv6 bool
	// Report receives fixed codes and messages only; no destinations or secrets.
	Report func(string, string)
	Stats  *telemetry.Counters
	DNS    []string
	DoH    *DoHResolver
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
	slots  chan struct{}
	// idle and halfIdle override the relay idle limits in tests.
	idle, halfIdle time.Duration
}

func NewHandler(ctx context.Context) *Handler {
	ctx, cancel := context.WithCancel(ctx)
	return &Handler{ctx: ctx, cancel: cancel, slots: make(chan struct{}, 512), Metadata: NewDNSMetadata()}
}
func (h *Handler) start(c net.Conn, run func(closeLocal func())) {
	h.mu.Lock()
	if h.closed || h.ctx.Err() != nil {
		h.mu.Unlock()
		_ = c.Close()
		return
	}
	select {
	case h.slots <- struct{}{}:
	default:
		h.mu.Unlock()
		_ = c.Close()
		return
	}
	h.wg.Add(1)
	h.mu.Unlock()
	go func() {
		defer guard.Recover()
		defer h.wg.Done()
		defer func() { <-h.slots }()
		closeLocal := sync.OnceFunc(func() { _ = c.Close() })
		defer closeLocal()
		stop := context.AfterFunc(h.ctx, closeLocal)
		defer stop()
		run(closeLocal)
	}()
}
func (h *Handler) Close() {
	h.mu.Lock()
	h.closed = true
	h.cancel()
	h.mu.Unlock()
	h.wg.Wait()
	h.DoH.Close()
}
func (h *Handler) report(code, message string) {
	if h.Report != nil && h.ctx.Err() == nil {
		h.Report(code, message)
	}
}
func (h *Handler) target(address string) (string, routing.Action, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", "", fmt.Errorf("netstack destination is not an IP")
	}
	if h.DisableIPv6 && ip.Unmap().Is6() {
		return address, routing.Block, nil
	}
	action := routing.Proxy
	if h.Policy != nil {
		action = h.Policy.DecideDomains(ip, h.Metadata.Domains(ip))
	}
	return address, action, nil
}
func (h *Handler) HandleTCP(c adapter.TCPConn) {
	if c.LocalAddr().String() == net.JoinHostPort(DNSAddress, "53") {
		h.handleDNSTCP(c)
		return
	}
	h.start(c, func(closeLocal func()) {
		target, action, err := h.target(c.LocalAddr().String())
		h.Stats.RouteDecided(action)
		if err != nil || action == routing.Block {
			return
		}
		d := h.TCP
		if action == routing.Direct {
			d = h.DirectTCP
		}
		if d == nil {
			return
		}
		h.Stats.AttemptTCP()
		ctx, cancel := context.WithTimeout(h.ctx, 15*time.Second)
		upstream, err := d.DialStream(ctx, target)
		cancel()
		if err != nil {
			h.Stats.FailTCP()
			return
		}
		h.Stats.EstablishTCP()
		defer h.Stats.EndTCP()
		closeUpstream := sync.OnceFunc(func() { _ = upstream.Close() })
		defer guard.CloseOnExit(closeUpstream)
		stop := context.AfterFunc(h.ctx, closeUpstream)
		defer stop()
		idleLimit, halfIdle := relay.IdleTimeout, relay.HalfClosedIdleTimeout
		if h.idle > 0 {
			idleLimit, halfIdle = h.idle, h.halfIdle
		}
		closeFlow := func() { closeLocal(); closeUpstream() }
		idle := relay.Watch(idleLimit, closeFlow)
		defer idle.Stop()
		done := make(chan struct{})
		go func() {
			defer guard.Recover()
			defer close(done)
			_, _ = h.Stats.CopyUp(idle.Writer(upstream), c)
			idle.SetLimit(halfIdle)
			_ = upstream.CloseWrite()
		}()
		_, err = h.Stats.CopyDown(idle.Writer(c), upstream)
		idle.SetLimit(halfIdle)
		// After upstream EOF the upload may continue until it has been idle
		// for the half-closed limit. Never strand a goroutine.
		if half, ok := c.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		if err != nil {
			// A failed download (reset, transport error) ends the flow, as in
			// the SOCKS5 relay.
			closeFlow()
		}
		select {
		case <-done:
		case <-h.ctx.Done():
			closeFlow()
			<-done
		}
	})
}
func (h *Handler) HandleUDP(c adapter.UDPConn) {
	if c.LocalAddr().String() == net.JoinHostPort(DNSAddress, "53") {
		h.handleDNSUDP(c)
		return
	}
	h.start(c, func(_ func()) {
		target, action, err := h.target(c.LocalAddr().String())
		h.Stats.RouteDecided(action)
		if err != nil || action == routing.Block {
			return
		}
		h.Stats.AttemptUDP()
		var upstream net.PacketConn
		var direct net.Conn
		if action == routing.Direct {
			if h.DirectUDP == nil {
				return
			}
			direct, err = h.DirectUDP.DialPacket(h.ctx, target)
			if err != nil {
				h.Stats.FailUDP()
				return
			}
			defer guard.CloseOnExit(func() { _ = direct.Close() })
		} else {
			if h.UDP == nil {
				return
			}
			upstream, err = h.UDP.ListenPacket(h.ctx)
			if err != nil {
				h.Stats.FailUDP()
				return
			}
			defer guard.CloseOnExit(func() { _ = upstream.Close() })
		}
		h.Stats.EstablishUDP()
		defer h.Stats.EndUDP()
		destination, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			return
		}
		closeUpstream := func() {
			if direct != nil {
				_ = direct.Close()
			} else {
				_ = upstream.Close()
			}
		}
		stop := context.AfterFunc(h.ctx, closeUpstream)
		defer stop()
		done := make(chan struct{})
		go func() {
			defer guard.Recover()
			defer close(done)
			defer c.Close()
			buffer := make([]byte, 16*1024)
			for {
				var n int
				var err error
				if direct != nil {
					_ = direct.SetReadDeadline(time.Now().Add(60 * time.Second))
					n, err = direct.Read(buffer)
				} else {
					_ = upstream.SetReadDeadline(time.Now().Add(60 * time.Second))
					var source net.Addr
					n, source, err = upstream.ReadFrom(buffer)
					// Each netstack UDP flow has a fixed destination. Ignore unrelated packets.
					if err == nil && source.String() != destination.String() {
						continue
					}
				}
				if err != nil {
					return
				}
				h.Stats.Received(int64(n))
				if _, err = c.Write(buffer[:n]); err != nil {
					return
				}
			}
		}()
		buffer := make([]byte, 16*1024)
		for {
			_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, _, err := c.ReadFrom(buffer)
			if err != nil {
				break
			}
			h.Stats.Sent(int64(n))
			if direct != nil {
				_, err = direct.Write(buffer[:n])
			} else {
				_, err = upstream.WriteTo(buffer[:n], destination)
			}
			if err != nil {
				break
			}
		}
		closeUpstream()
		<-done
	})
}
