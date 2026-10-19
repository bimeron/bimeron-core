// Package androidcore exposes the packet engine to an Android VpnService.
// Build it as an AAR with gomobile bind; it does not create a VPN interface.
package androidcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"bimeron/core"
)

// SocketProtector is implemented by the VpnService. Protect must call
// VpnService.protect(fd) before the socket is connected. It may also bind the
// socket to the selected physical Network. Returning false blocks the dial.
type SocketProtector interface {
	Protect(fd int) bool
}

// Session is single-use: create a new one for each VPN start.
type Session struct {
	mu         sync.RWMutex
	lifecycle  sync.Mutex
	engine     *core.Engine
	port       *core.PacketPort
	config     core.SessionConfig
	protector  SocketProtector
	networkID  string
	dns        []string
	generation uint64
	stopped    bool
}

// NewSession copies and validates an inline profile. No network is configured
// until the host calls SetNetwork and Start.
func NewSession(profile []byte, protector SocketProtector) (*Session, error) {
	if protector == nil {
		return nil, errors.New("socket protector required")
	}
	c, err := core.LoadConfigData(profile)
	if err != nil {
		return nil, err
	}
	if c.Mode != "vpn" || c.KillSwitch {
		return nil, errors.New("Android packet VPN requires vpn mode without core kill switch")
	}
	s := &Session{config: c, protector: protector}
	s.engine, s.port, err = core.NewPacketEngine(core.Options{}, core.PacketOptions{MTU: c.MTU, Outbound: s.outbound})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// SetNetwork supplies the current physical path and its IPv4 DNS servers.
// An empty ID means unavailable. Call it when the underlying network changes.
func (s *Session) SetNetwork(id, dns string) error {
	servers := []string{}
	if dns != "" {
		for _, value := range strings.Split(dns, ",") {
			ip, err := netip.ParseAddr(strings.TrimSpace(value))
			if err != nil || !ip.Is4() {
				return errors.New("physical DNS must contain IPv4 addresses")
			}
			servers = append(servers, ip.String())
		}
	}
	if len(servers) > 4 {
		return errors.New("at most four physical DNS servers are supported")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.networkID != id || strings.Join(s.dns, ",") != strings.Join(servers, ",") {
		s.networkID, s.dns = id, servers
		s.generation++
	}
	return nil
}

func (s *Session) outbound(ctx context.Context) (core.PacketNetwork, error) {
	if err := ctx.Err(); err != nil {
		return core.PacketNetwork{}, err
	}
	s.mu.RLock()
	id, generation := s.networkID, s.generation
	dns := append([]string(nil), s.dns...)
	s.mu.RUnlock()
	if id == "" {
		return core.PacketNetwork{}, errors.New("physical network unavailable")
	}
	return core.PacketNetwork{
		Identity: fmt.Sprintf("%s:%d", id, generation),
		DNS:      dns,
		Dialer: net.Dialer{Timeout: 15 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
			var protectErr error
			if err := raw.Control(func(fd uintptr) {
				if !s.protector.Protect(int(fd)) {
					protectErr = errors.New("VpnService.protect failed")
				}
			}); err != nil {
				return err
			}
			return protectErr
		}},
	}, nil
}

// Start accepts the request; Status reports when the tunnel is connected.
func (s *Session) Start() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.stopped {
		return errors.New("Android session already stopped")
	}
	return s.engine.Start(context.Background(), s.config)
}

func (s *Session) WritePacket(packet []byte) error { return s.port.WritePacket(packet) }

// ReadPacket returns nil on timeout. Stop unblocks a pending read.
func (s *Session) ReadPacket(timeoutMs int) ([]byte, error) {
	if timeoutMs < 1 || timeoutMs > 1000 {
		return nil, errors.New("packet read timeout must be 1..1000 ms")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	packet, err := s.port.ReadPacket(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, nil
	}
	return packet, err
}

func (s *Session) Status() string {
	b, _ := json.Marshal(struct {
		Status core.Status `json:"status"`
		Stats  any         `json:"stats"`
	}{s.engine.Status(), s.engine.Stats()})
	return string(b)
}

// Events drains up to eight best-effort diagnostic events.
func (s *Session) Events() string {
	events := make([]core.Event, 0, 8)
	for len(events) < cap(events) {
		select {
		case event := <-s.engine.Events():
			events = append(events, event)
		default:
			b, _ := json.Marshal(events)
			return string(b)
		}
	}
	b, _ := json.Marshal(events)
	return string(b)
}

func (s *Session) MTU() int          { return s.config.MTU }
func (s *Session) DisableIPv6() bool { return s.config.DisableIPv6 }

// Stop closes the packet port immediately and waits for core cleanup. Retry
// Stop if its deadline expires; do not reuse this Session for another Start.
func (s *Session) Stop() error {
	s.lifecycle.Lock()
	s.stopped = true
	s.port.Close()
	s.lifecycle.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return s.engine.Stop(ctx)
}

func Version() string {
	b, _ := json.Marshal(core.GetBuildInfo())
	return string(b)
}

// Capabilities describes this embedded Android packet backend, not the
// unsupported standalone Android platform backend reported by core.New.
func Capabilities() string {
	b, _ := json.Marshal(core.Capabilities{Platform: "android", VPN: true, IPv4: true, IPv6: true, IPSplit: true, DomainSplit: true})
	return string(b)
}
