package core

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"

	"bimeron/internal/accesskey"
)

// Control-plane connections use this resolver for ssconf and upstream endpoints.
// SOCKS5 relay hostnames also use it; user traffic uses the packet handler.
func bootstrapDialer(path networkPath, fallback []string) net.Dialer {
	base := path.dialer
	servers := path.dns
	if len(servers) == 0 {
		servers = fallback
	}
	var next atomic.Uint64
	base.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if len(servers) == 0 {
			return nil, fault("bootstrap_dns_unavailable", true)
		}
		server := servers[(next.Add(1)-1)%uint64(len(servers))]
		ip, err := netip.ParseAddr(server)
		if err != nil || !ip.Is4() {
			return nil, fault("bootstrap_dns_invalid", true)
		}
		// Use a resolver-free copy to avoid recursively resolving a DNS server.
		protocol := "udp4"
		if network == "tcp" {
			protocol = "tcp4"
		}
		return path.dialer.DialContext(ctx, protocol, net.JoinHostPort(ip.String(), "53"))
	}}
	return base
}
func resolveOnPath(ctx context.Context, c SessionConfig, path networkPath) (Profile, net.Dialer, sessionEndpoints, error) {
	d := bootstrapDialer(path, c.DNS)
	t := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp4", address)
	}}
	defer t.CloseIdleConnections()
	resolve := c.Resolve
	if c.ResolveOnNetwork != nil {
		resolve = func(ctx context.Context) (Profile, error) { return c.ResolveOnNetwork(ctx, t) }
	}
	p, err := resolve(ctx)
	if err != nil {
		if accesskey.IsUnavailable(err) {
			return Profile{}, d, sessionEndpoints{}, fault("access_key_unavailable", false)
		}
		return Profile{}, d, sessionEndpoints{}, fault("access_key_resolve_failed", true)
	}
	original := p
	if p.Type == "vless" && p.VLESS.XHTTPOptions != nil && p.VLESS.XHTTPOptions.DownloadSettings != nil {
		options := *p.VLESS.XHTTPOptions
		downloadCopy := *options.DownloadSettings
		options.DownloadSettings = &downloadCopy
		p.VLESS.XHTTPOptions = &options
		download := options.DownloadSettings
		ips, err := d.Resolver.LookupNetIP(ctx, "ip", download.Address)
		if err != nil || len(ips) == 0 {
			return Profile{}, d, sessionEndpoints{}, fault("endpoint_dns_failed", true)
		}
		chosen := ips[0]
		for _, ip := range ips {
			if ip.Is4() {
				chosen = ip
				break
			}
		}
		download.ResolvedAddress = chosen.Unmap().String()
	}
	for _, ep := range []*Endpoint{&p.TCP, &p.UDP} {
		if p.Type == "ssh" || (p.Type == "http" && ep == &p.UDP) {
			continue
		}
		family := "ip4"
		if p.Type == "vless" || p.Type == "trojan" || p.Type == "vmess" || p.Type == "hysteria2" || p.Type == "tuic" || p.Type == "http" {
			family = "ip"
		}
		ips, err := d.Resolver.LookupNetIP(ctx, family, ep.Host)
		if err != nil || len(ips) == 0 {
			if p.Type == "hysteria2" {
				return Profile{}, d, sessionEndpoints{}, &stageError{code: "hysteria2_network_failed", retry: true, stage: "endpoint_resolution"}
			}
			return Profile{}, d, sessionEndpoints{}, fault("endpoint_dns_failed", true)
		}
		chosen := ips[0]
		for _, ip := range ips {
			if ip.Is4() {
				chosen = ip
				break
			}
		}
		ep.Host = chosen.Unmap().String()
	}
	domain := func(host string) string {
		if _, err := netip.ParseAddr(host); err == nil {
			return ""
		}
		return host
	}
	endpoints := sessionEndpoints{
		tcp:     net.JoinHostPort(p.TCP.Host, strconv.Itoa(p.TCP.Port)),
		tcpName: domain(original.TCP.Host), udpName: domain(original.UDP.Host),
	}
	if p.Type != "ssh" && p.Type != "http" {
		endpoints.udp = net.JoinHostPort(p.UDP.Host, strconv.Itoa(p.UDP.Port))
	}
	return p, d, endpoints, nil
}
