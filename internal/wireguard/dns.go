package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsAttemptTimeout bounds one exchange with one resolver; the next
// resolver is tried after it.
const dnsAttemptTimeout = 2 * time.Second

// lookup resolves A and AAAA records through Bimeron's resolvers. Queries
// use the client's own scoped UDP path, so they follow AllowedIPs like any
// other traffic. Each resolver gets one bounded exchange; a silent or
// failing resolver moves the lookup to the next one.
func (c *Client) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil || len(c.dns) == 0 {
		return nil, errResolve
	}
	for _, server := range c.dns {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		ips, ok := c.exchange(ctx, server, name)
		if ok {
			if len(ips) == 0 {
				return nil, errResolve
			}
			return ips, nil
		}
	}
	return nil, errResolve
}

// exchange asks one resolver for A and AAAA records. ok is false when the
// resolver did not answer both questions validly in time.
func (c *Client) exchange(ctx context.Context, server netip.AddrPort, name dnsmessage.Name) ([]netip.Addr, bool) {
	ctx, cancel := context.WithTimeout(ctx, dnsAttemptTimeout)
	defer cancel()
	pc, err := c.ListenPacket(ctx)
	if err != nil {
		return nil, false
	}
	defer pc.Close()
	stop := context.AfterFunc(ctx, func() { _ = pc.SetReadDeadline(time.Now()) })
	defer stop()
	to := net.UDPAddrFromAddrPort(server)
	pending := map[uint16]dnsmessage.Type{}
	for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		var b [2]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, false
		}
		id := binary.BigEndian.Uint16(b[:])
		q := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: t, Class: dnsmessage.ClassINET}}}
		packet, err := q.Pack()
		if err != nil {
			return nil, false
		}
		if _, err := pc.WriteTo(packet, to); err != nil {
			return nil, false
		}
		pending[id] = t
	}
	var ips []netip.Addr
	buf := make([]byte, 4096)
	for len(pending) > 0 {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return nil, false
		}
		if u, ok := from.(*net.UDPAddr); !ok || u.AddrPort() != server {
			continue
		}
		var m dnsmessage.Message
		if m.Unpack(buf[:n]) != nil || !m.Response || len(m.Questions) != 1 {
			continue
		}
		t, ok := pending[m.ID]
		if !ok || m.Questions[0].Type != t || !strings.EqualFold(m.Questions[0].Name.String(), name.String()) {
			continue
		}
		switch m.RCode {
		case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
		default:
			// SERVFAIL, REFUSED and the like: try another resolver.
			return nil, false
		}
		delete(pending, m.ID)
		for _, a := range m.Answers {
			switch body := a.Body.(type) {
			case *dnsmessage.AResource:
				ips = append(ips, netip.AddrFrom4(body.A))
			case *dnsmessage.AAAAResource:
				ips = append(ips, netip.AddrFrom16(body.AAAA))
			}
		}
	}
	return ips, true
}
