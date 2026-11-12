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
	"bimeron/internal/sshtunnel"
)

// SocketProtector is implemented by the VpnService. Protect must call
// VpnService.protect(fd) before the socket is connected. It may also bind the
// socket to the selected physical Network. Returning false blocks the dial.
type SocketProtector interface {
	Protect(fd int) bool
}

// Session is single-use: create a new one for each VPN start.
type Session struct {
	auth       authBridge
	mu         sync.RWMutex
	lifecycle  sync.Mutex
	engine     *core.Engine
	port       *core.PacketPort
	config     core.SessionConfig
	protector  SocketProtector
	networkID  string
	dns        []string
	generation uint64
	started    bool
	stopped    bool
}

// NewSession copies and validates an inline profile. No network is configured
// until the host calls SetNetwork and Start.
func NewSession(profile []byte, protector SocketProtector) (*Session, error) {
	return NewSessionWithGeoData(profile, nil, nil, protector)
}

// NewSessionWithGeoData validates explicit dataset bytes without filesystem access.
func NewSessionWithGeoData(profile, geoIP, geoSite []byte, protector SocketProtector) (*Session, error) {
	if protector == nil {
		return nil, errors.New("socket protector required")
	}
	c, err := core.LoadConfigDataWithGeoData(profile, geoIP, geoSite)
	if err != nil {
		return nil, err
	}
	return newSession(c, protector)
}

// newSession is the only constructor of a startable Session; every exported
// constructor goes through it.
func newSession(c core.SessionConfig, protector SocketProtector) (*Session, error) {
	if err := core.ValidateEmbeddedHost(c); err != nil {
		return nil, err
	}
	// SSH on Android uses only files the app imported and named in the
	// profile: no default identity scan, no ~/.ssh/known_hosts fallback, no
	// "~" paths and no SSH agent. A profile needs a KnownHostsFile or
	// AcceptNewHostKeys, otherwise LastError is ssh_known_hosts_missing.
	c.SSHDefaultKeys, c.SSHProfileOnly = false, true
	s := &Session{config: c, protector: protector}
	s.auth.id = opaqueID()
	var err error
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
		s.auth.invalidate(s.generation, false)
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
		Identity:  fmt.Sprintf("%s:%d", id, generation),
		DNS:       dns,
		SSHPrompt: s.auth.prompt(generation),
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
	s.started = true
	return s.engine.Start(context.Background(), s.config)
}

// AcceptNewHostKeys opts this Session in to SSH accept-new host-key handling.
// Call it at most once, before Start. trustedKnownHosts holds the app-owned
// known_hosts lines for this profile (empty or nil for none); only plain
// "host[,host] type base64 [comment]" lines are accepted. The profile's
// KnownHostsFile, if set, is still trusted. No default file is ever read on
// Android; without KnownHostsFile and without this call, an SSH profile fails
// with ssh_known_hosts_missing.
//
// An unknown host then produces a pendingAuth offer of kind "host_key"; a host
// known from either source with a different key fails with fault
// ssh_host_key_mismatch and no offer. Keys accepted here are remembered for
// this Session's reconnects; the app persists knownHostsLine itself.
func (s *Session) AcceptNewHostKeys(trustedKnownHosts []byte) error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.started || s.stopped || s.config.SSHHostKeys != nil {
		return errors.New("host keys must be configured once before Start")
	}
	keys, err := sshtunnel.ParseHostKeys(trustedKnownHosts)
	if err != nil {
		return err
	}
	s.config.SSHHostKeys = keys
	return nil
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
	s.mu.Lock()
	s.auth.invalidate(s.generation, true)
	s.mu.Unlock()
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
	c := core.PlatformCapabilities()
	c = core.Capabilities{Platform: "android", VPN: true, IPv4: true, IPv6: true, IPSplit: true, DomainSplit: true, GeoIPSplit: true, GeoSiteSplit: true, GeoDataSchema: c.GeoDataSchema, ExplicitAccess: c.ExplicitAccess}
	b, _ := json.Marshal(c)
	return string(b)
}

// GeoDataGroups returns JSON with groups (an array) and error (null or a string).
func GeoDataGroups(kind string, data []byte) string {
	groups, err := core.GeoDataGroups(kind, data)
	if groups == nil {
		groups = []string{}
	}
	return geoDataJSON(groups, err)
}

// ValidateConfigWithGeoData returns JSON with error null on success and adds
// problems on failure; see docs/ERRORS.MD. It also enforces
// this embedded host's mode and kill-switch restrictions.
func ValidateConfigWithGeoData(profile, geoIP, geoSite []byte) string {
	c, err := core.LoadConfigDataWithGeoData(profile, geoIP, geoSite)
	if err == nil {
		err = core.ValidateEmbeddedHost(c)
	}
	return geoDataJSON(nil, err)
}

// ErrorCatalog returns the JSON catalog of human-readable error texts.
func ErrorCatalog() string {
	b, _ := core.ErrorCatalog()
	return string(b)
}

func geoDataJSON(groups []string, err error) string {
	var message *string
	if err != nil {
		value := err.Error()
		message = &value
	}
	var details *core.GeoDataError
	errors.As(err, &details)
	b, _ := json.Marshal(struct {
		Groups   []string           `json:"groups"`
		Error    *string            `json:"error"`
		Details  *core.GeoDataError `json:"details,omitempty"`
		Problems []*core.Problem    `json:"problems,omitempty"`
	}{groups, message, details, problems(err)})
	return string(b)
}

// problems lists structured failures; success keeps the historical JSON
// without a problems field.
func problems(err error) []*core.Problem {
	if err == nil {
		return nil
	}
	return core.Problems(err)
}
