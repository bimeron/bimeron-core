package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"bimeron/internal/accesskey"
	"bimeron/internal/anytls"
	"bimeron/internal/hysteria2"
	"bimeron/internal/naive"
	"bimeron/internal/proxy"
	"bimeron/internal/sshtunnel"
	"bimeron/internal/trojan"
	"bimeron/internal/tuic"
	"bimeron/internal/vless"
	"bimeron/internal/vmess"
	"bimeron/internal/vpn"
	"golang.getoutline.org/sdk/transport"
)

// platform isolates adapter, route and DNS operations. Transport, policy, DNS
// forwarding, retries and session state are shared across operating systems.
type platform interface {
	Acquire(context.Context) (func(), error)
	Inspect(context.Context, string, bool) (networkPath, error)
	Open(context.Context, SessionConfig, *flowRouter, func(string, string)) (link, error)
}
type networkPath struct {
	identity string
	dialer   net.Dialer
	dns      []string
	refresh  func(context.Context) error
}
type link interface{ Close() error }

func hysteria2Fault(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	var failure *hysteria2.Failure
	if errors.As(err, &failure) {
		return &stageError{code: failure.Code, retry: failure.Retry, stage: failure.Stage}
	}
	return fault("hysteria2_unknown", false)
}

type vpnBackend struct {
	platform platform
	metadata *vpn.DNSMetadata
}

func newBackend(c SessionConfig) backend {
	if c.IKEv2 != nil {
		return newIKEv2Backend()
	}
	if c.Mode == "proxy" {
		return proxyBackend{}
	}
	return &vpnBackend{platform: newPlatform(c), metadata: vpn.NewDNSMetadata()}
}
func (b *vpnBackend) Acquire(ctx context.Context) (func(), error) { return b.platform.Acquire(ctx) }
func (b *vpnBackend) Open(ctx context.Context, c SessionConfig, report func(string, string)) (session, error) {
	setupCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	report("network_inspect", "Selecting outbound network interface")
	path, err := b.platform.Inspect(setupCtx, c.Name, true)
	if err != nil {
		return nil, err
	}
	h, tcp, udp, closeTransport, err := prepareVPN(ctx, setupCtx, c, path, report, b.metadata)
	if err != nil {
		return nil, err
	}
	router := &flowRouter{}
	router.replace(h)
	l, err := b.platform.Open(setupCtx, c, router, report)
	if err != nil {
		router.Close()
		if closeTransport != nil {
			_ = closeTransport()
		}
		return nil, err
	}
	return &vpnSession{link: l, router: router, platform: b.platform, path: path, cfg: c, tcp: tcp, udp: udp, closeTransport: closeTransport, report: report, ctx: ctx, metadata: b.metadata, prepare: prepareVPN}, nil
}

func directHandler(ctx context.Context, c SessionConfig, path networkPath, report func(string, string), metadata *vpn.DNSMetadata) *vpn.Handler {
	h := vpn.NewHandler(ctx)
	h.Metadata = metadata
	h.Stats = c.stats
	h.DirectTCP = &transport.TCPDialer{Dialer: path.dialer}
	h.DirectUDP = &transport.UDPDialer{Dialer: path.dialer}
	h.Policy = c.Policy
	h.DNS = c.DNS
	h.DisableIPv6 = c.DisableIPv6
	h.Report = report
	return h
}
func prepareVPN(lifetime, ctx context.Context, c SessionConfig, path networkPath, report func(string, string), metadata *vpn.DNSMetadata) (*vpn.Handler, transport.StreamDialer, transport.PacketListener, func() error, error) {
	report("key_resolve", "Resolving access key through outbound interface")
	p, outbound, endpoints, err := resolveOnPath(ctx, c, path)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var tcp transport.StreamDialer
	var udp transport.PacketListener
	var closeTransport func() error
	if p.Type == "socks5" {
		s := &proxy.SOCKS5{Endpoint: p.TCP, Username: p.Username, Dialer: outbound}
		tcp, udp = s, s
	} else if p.Type == "http" {
		tcp = &proxy.HTTPConnect{Endpoint: p.TCP, Username: p.Username, Dialer: outbound}
	} else if p.Type == "vless" {
		client, clientErr := vless.New(p, outbound)
		if clientErr != nil {
			return nil, nil, nil, nil, fault("invalid_tcp_transport", false)
		}
		tcp, udp, closeTransport = client, client, client.Close
	} else if p.Type == "trojan" {
		client, clientErr := trojan.New(p, outbound)
		if clientErr != nil {
			return nil, nil, nil, nil, fault("invalid_tcp_transport", false)
		}
		tcp, udp, closeTransport = client, client, client.Close
	} else if p.Type == "anytls" {
		client, clientErr := anytls.New(p, outbound)
		if clientErr != nil {
			return nil, nil, nil, nil, fault("invalid_tcp_transport", false)
		}
		tcp, udp, closeTransport = client, client, client.Close
	} else if p.Type == "vmess" {
		client, clientErr := vmess.New(p, outbound)
		if clientErr != nil {
			return nil, nil, nil, nil, fault("invalid_tcp_transport", false)
		}
		tcp, udp, closeTransport = client, client, client.Close
	} else if p.Type == "hysteria2" {
		client, clientErr := hysteria2.New(ctx, p, outbound)
		if clientErr != nil {
			return nil, nil, nil, nil, hysteria2Fault(clientErr)
		}
		tcp, udp, closeTransport = client, client, client.Close
	} else if p.Type == "ssh" {
		client, clientErr := sshtunnel.New(ctx, p, outbound, c.SSHPrompt, c.SSHDefaultKeys)
		if clientErr != nil {
			return nil, nil, nil, nil, fault("ssh_connection_failed", false)
		}
		tcp, closeTransport = client, client.Close
	} else if p.Type == "naive" {
		client, clientErr := naive.New(p, outbound)
		if clientErr != nil {
			return nil, nil, nil, nil, fault("invalid_tcp_transport", false)
		}
		tcp, closeTransport = client, client.Close
	} else if p.Type == "tuic" {
		client, clientErr := tuic.New(p, outbound)
		if clientErr != nil {
			return nil, nil, nil, nil, fault("invalid_tcp_transport", false)
		}
		tcp, udp, closeTransport = client, client, client.Close
	} else {
		tcp, err = proxy.OutlineTCP(p.TCP, path.dialer)
		if err != nil {
			return nil, nil, nil, nil, fault("invalid_tcp_transport", false)
		}
		udp, err = proxy.OutlineUDP(p.UDP, path.dialer)
		if err != nil {
			return nil, nil, nil, nil, fault("invalid_udp_transport", false)
		}
	}
	if p.Type == "ssh" || p.Type == "http" || p.Type == "naive" {
		report("transport_check", "Checking TCP/TLS and DNS over TCP-only upstream")
	} else {
		report("transport_check", "Checking TCP/TLS and UDP/DNS")
	}
	if _, err := vpn.Check(ctx, tcp, udp, c.DNS); err != nil {
		if closeTransport != nil {
			_ = closeTransport()
		}
		return nil, nil, nil, nil, fault("transport_check_failed", true)
	}
	if c.endpointChanged != nil {
		c.endpointChanged(endpoints)
	}
	h := directHandler(lifetime, c, path, report, metadata)
	h.TCP = tcp
	h.UDP = udp
	return h, tcp, udp, closeTransport, nil
}

type vpnSession struct {
	link           link
	router         *flowRouter
	platform       platform
	path           networkPath
	cfg            SessionConfig
	tcp            transport.StreamDialer
	udp            transport.PacketListener
	closeTransport func() error
	report         func(string, string)
	ctx            context.Context
	metadata       *vpn.DNSMetadata
	prepare        func(context.Context, context.Context, SessionConfig, networkPath, func(string, string), *vpn.DNSMetadata) (*vpn.Handler, transport.StreamDialer, transport.PacketListener, func() error, error)
}

func (s *vpnSession) Close() error {
	err := s.link.Close()
	s.router.Close()
	if s.closeTransport != nil {
		_ = s.closeTransport()
	}
	return err
}

// Suspend replaces the failed generation with direct-only policy handling.
// The adapter, routes, NRPT and packet stack stay owned by this session.
func (s *vpnSession) Suspend() {
	s.router.replace(directHandler(s.ctx, s.cfg, s.path, s.report, s.metadata))
}
func (s *vpnSession) Reconnect(ctx context.Context) error {
	attempt, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	path, err := s.platform.Inspect(attempt, s.cfg.Name, false)
	if err != nil {
		return err
	}
	if path.identity != s.path.identity {
		s.router.replace(directHandler(s.ctx, s.cfg, path, s.report, s.metadata))
		s.path = path
	}
	h, tcp, udp, closeTransport, err := s.prepare(s.ctx, attempt, s.cfg, path, s.report, s.metadata)
	if err != nil {
		return err
	}
	if path.refresh != nil {
		if err := path.refresh(attempt); err != nil {
			s.report("dns_refresh_failed", "Could not refresh system DNS state")
		}
	}
	if ctx.Err() != nil {
		h.Close()
		if closeTransport != nil {
			_ = closeTransport()
		}
		return ctx.Err()
	}
	s.router.replace(h)
	if s.closeTransport != nil {
		_ = s.closeTransport()
	}
	s.tcp = tcp
	s.udp = udp
	s.closeTransport = closeTransport
	s.path = path
	return nil
}
func (s *vpnSession) Wait(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	now := time.Now()
	monitor := healthMonitor{identity: s.path.identity, last: now, lastProbe: now, clock: time.Now, report: s.report,
		inspect: func(ctx context.Context) (string, error) {
			p, err := s.platform.Inspect(ctx, s.cfg.Name, false)
			return p.identity, err
		},
		probe: func(ctx context.Context) error { _, err := vpn.Check(ctx, s.tcp, s.udp, s.cfg.DNS); return err },
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		if err := monitor.step(ctx, time.Now()); err != nil {
			return err
		}
	}
}

// A separate monitor makes network changes, failures and resume testable without
// changing the host's network or waiting for real sleep/probe intervals.
type healthMonitor struct {
	identity        string
	last, lastProbe time.Time
	failures        int
	clock           func() time.Time
	inspect         func(context.Context) (string, error)
	probe           func(context.Context) error
	report          func(string, string)
}

func (m *healthMonitor) step(ctx context.Context, now time.Time) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if resumed(m.last, now) {
		return fault("resume_detected", true)
	}
	m.last = now
	inspectCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	identity, err := m.inspect(inspectCtx)
	cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		var staged *stageError
		if errors.As(err, &staged) && !staged.retry {
			return err
		}
		return fault("network_unavailable", true)
	}
	if identity != m.identity {
		return fault("network_changed", true)
	}
	if now.Sub(m.lastProbe) < 30*time.Second {
		return nil
	}
	m.lastProbe = now
	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err = m.probe(probeCtx)
	cancel()
	// The bounded probe itself must not be mistaken for system sleep.
	m.last = m.clock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		m.failures = 0
		return nil
	}
	m.failures++
	m.report("health_check_failed", "Transport health check failed")
	if m.failures >= 3 {
		return fault("transport_unavailable", true)
	}
	return nil
}
func resumed(last, now time.Time) bool { return now.UnixNano()-last.UnixNano() > int64(30*time.Second) }

// cleanup executes every registered action, even after a failure. Open can use
// the same object for rollback and normal Stop without double-releasing resources.
type cleanup struct {
	once    sync.Once
	actions []func() error
	err     error
}

func (c *cleanup) add(f func() error) { c.actions = append(c.actions, f) }
func (c *cleanup) Close() error {
	c.once.Do(func() {
		for i := len(c.actions) - 1; i >= 0; i-- {
			if err := c.actions[i](); err != nil {
				c.err = fault("cleanup_failed_run_recover", false)
			}
		}
	})
	return c.err
}

type proxyBackend struct{}

func (proxyBackend) Acquire(context.Context) (func(), error) { return func() {}, nil }
func (proxyBackend) Open(ctx context.Context, c SessionConfig, report func(string, string)) (session, error) {
	resolveCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p, err := c.Resolve(resolveCtx)
	if err != nil {
		if accesskey.IsUnavailable(err) {
			return nil, fault("access_key_unavailable", false)
		}
		return nil, fault("access_key_resolve_failed", true)
	}
	var d transport.StreamDialer
	var closeTransport func() error
	if p.Type == "socks5" {
		d = &proxy.SOCKS5{Endpoint: p.TCP, Username: p.Username, Dialer: net.Dialer{Timeout: 15 * time.Second}}
	} else if p.Type == "http" {
		d = &proxy.HTTPConnect{Endpoint: p.TCP, Username: p.Username, Dialer: net.Dialer{Timeout: 15 * time.Second}}
	} else if p.Type == "vless" {
		client, clientErr := vless.New(p, net.Dialer{Timeout: 15 * time.Second})
		if clientErr != nil {
			return nil, fault("invalid_tcp_transport", false)
		}
		d, closeTransport = client, client.Close
	} else if p.Type == "trojan" {
		client, clientErr := trojan.New(p, net.Dialer{Timeout: 15 * time.Second})
		if clientErr != nil {
			return nil, fault("invalid_tcp_transport", false)
		}
		d, closeTransport = client, client.Close
	} else if p.Type == "anytls" {
		client, clientErr := anytls.New(p, net.Dialer{Timeout: 15 * time.Second})
		if clientErr != nil {
			return nil, fault("invalid_tcp_transport", false)
		}
		d, closeTransport = client, client.Close
	} else if p.Type == "vmess" {
		client, clientErr := vmess.New(p, net.Dialer{Timeout: 15 * time.Second})
		if clientErr != nil {
			return nil, fault("invalid_tcp_transport", false)
		}
		d, closeTransport = client, client.Close
	} else if p.Type == "hysteria2" {
		client, clientErr := hysteria2.New(resolveCtx, p, net.Dialer{Timeout: 15 * time.Second})
		if clientErr != nil {
			return nil, hysteria2Fault(clientErr)
		}
		d, closeTransport = client, client.Close
	} else if p.Type == "ssh" {
		client, clientErr := sshtunnel.New(resolveCtx, p, net.Dialer{Timeout: 15 * time.Second}, c.SSHPrompt, c.SSHDefaultKeys)
		if clientErr != nil {
			return nil, fault("ssh_connection_failed", false)
		}
		d, closeTransport = client, client.Close
	} else if p.Type == "naive" {
		client, clientErr := naive.New(p, net.Dialer{Timeout: 15 * time.Second})
		if clientErr != nil {
			return nil, fault("invalid_tcp_transport", false)
		}
		d, closeTransport = client, client.Close
	} else if p.Type == "tuic" {
		client, clientErr := tuic.New(p, net.Dialer{Timeout: 15 * time.Second})
		if clientErr != nil {
			return nil, fault("invalid_tcp_transport", false)
		}
		d, closeTransport = client, client.Close
	} else {
		d, err = proxy.Outline(p.TCP)
		if err != nil {
			return nil, fault("invalid_tcp_transport", false)
		}
	}
	l, err := net.Listen("tcp", c.Listen)
	if err != nil {
		if closeTransport != nil {
			_ = closeTransport()
		}
		return nil, fault("proxy_listener_failed", false)
	}
	serveCtx, stop := context.WithCancel(ctx)
	if c.endpointChanged != nil {
		c.endpointChanged(sessionEndpoints{tcp: net.JoinHostPort(p.TCP.Host, strconv.Itoa(p.TCP.Port))})
	}
	s := &proxySession{cancel: stop, done: make(chan struct{}), listener: l, closeTransport: closeTransport}
	report("proxy_listen", fmt.Sprintf("SOCKS5 TCP listening on %s", l.Addr()))
	go func() {
		s.err = (&proxy.Server{Proxy: d, Policy: c.Policy, Stats: c.stats}).Serve(serveCtx, l)
		close(s.done)
	}()
	return s, nil
}

type proxySession struct {
	cancel         context.CancelFunc
	done           chan struct{}
	listener       net.Listener
	err            error
	closeTransport func() error
}

func (s *proxySession) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		if s.err != nil {
			return fault("proxy_listener_failed", false)
		}
		return nil
	}
}
func (s *proxySession) Close() error {
	s.cancel()
	_ = s.listener.Close()
	<-s.done
	if s.closeTransport != nil {
		return s.closeTransport()
	}
	return nil
}
