package core

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"bimeron/internal/dnsconfig"
	"bimeron/internal/problem"
	"bimeron/internal/vpn"
	"bimeron/internal/wireguard"
)

// wireguardHandshakeTimeout bounds the wait for the first handshake; the
// engine retries initiations every few seconds meanwhile.
const wireguardHandshakeTimeout = 20 * time.Second

// startWireGuard starts a device on the outbound path and reports connected
// only after a completed handshake. The endpoint host is already an IP on the
// VPN path; proxy mode resolves it here.
func startWireGuard(ctx context.Context, c SessionConfig, p Profile, outbound net.Dialer, report func(string, string)) (*wireguard.Client, error) {
	if p.WireGuard == nil {
		return nil, fault("invalid_wireguard_transport", false)
	}
	if err := dnsconfig.ValidateDoHScope(c.doh, p.WireGuard.Peer.AllowedIPs, c.DisableIPv6); err != nil {
		return nil, fault(problem.Of(err).Code, false)
	}
	ip, err := netip.ParseAddr(p.UDP.Host)
	if err != nil {
		resolver := outbound.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		ips, lookupErr := resolver.LookupNetIP(ctx, "ip", p.UDP.Host)
		if lookupErr != nil || len(ips) == 0 {
			return nil, fault("endpoint_dns_failed", true)
		}
		ip = ips[0]
		for _, candidate := range ips {
			if candidate.Unmap().Is4() {
				ip = candidate
				break
			}
		}
	}
	client, err := wireguard.New(wireguard.Options{
		Config:   p.WireGuard,
		Endpoint: netip.AddrPortFrom(ip.Unmap(), uint16(p.UDP.Port)),
		Mode:     c.AllowedIPsMode,
		Outbound: outbound,
		DNS:      c.DNS,
	})
	switch {
	case errors.Is(err, wireguard.ErrSocket):
		// The outbound path may recover, for example after a network change.
		return nil, fault("wireguard_socket_failed", true)
	case errors.Is(err, wireguard.ErrPlatformLimit):
		return nil, fault("wireguard_platform_limit", false)
	case err != nil:
		return nil, fault("invalid_wireguard_transport", false)
	}
	report("wireguard_handshake", "Waiting for the WireGuard handshake")
	wait, cancel := context.WithTimeout(ctx, wireguardHandshakeTimeout)
	defer cancel()
	if err := client.WaitHandshake(wait); err != nil {
		_ = client.Close()
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, context.Canceled
		}
		return nil, fault("wireguard_handshake_timeout", true)
	}
	client.DoH = vpn.NewDoHResolver(client.DNSDialer(), c.doh, c.DisableIPv6)
	return client, nil
}
