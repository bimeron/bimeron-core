package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"bimeron/internal/guard"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsAttemptTimeout bounds one exchange with one resolver; the next
// resolver is tried after it.
const dnsAttemptTimeout = 2 * time.Second

var errNoSuchName = errors.New("WireGuard name does not exist")

// lookup resolves A and AAAA records through Bimeron's resolvers. Queries
// use the client's own scoped paths, so they follow AllowedIPs like any
// other traffic. Each resolver gets one bounded exchange. A resolver that
// answers neither question moves the lookup to the next one; a validated
// NXDOMAIN ends it.
func (c *Client) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil || len(c.dns) == 0 {
		return nil, errResolve
	}
	for _, server := range c.dns {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		ips, err := c.exchange(ctx, server, name)
		switch {
		case errors.Is(err, errNoSuchName):
			return nil, errResolve
		case errors.Is(err, ErrClosed):
			return nil, ErrClosed
		case err == nil && len(ips) > 0:
			return ips, nil
		}
	}
	return nil, errResolve
}

// reply is the outcome of one question.
type reply struct {
	id      uint16
	rcode   dnsmessage.RCode
	answers []dnsmessage.Resource
}

// exchange asks one resolver for A and AAAA records over UDP. A truncated
// reply is retried over TCP in the background while UDP keeps being read.
// It returns the addresses of every answered question and fails only when
// none was answered; a validated NXDOMAIN ends it at once.
func (c *Client) exchange(ctx context.Context, server netip.AddrPort, name dnsmessage.Name) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsAttemptTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	pc, err := c.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	_ = pc.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = pc.SetDeadline(time.Now()) })
	defer stop()
	to := net.UDPAddrFromAddrPort(server)
	types := map[uint16]dnsmessage.Type{}
	for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		id, err := newID(types)
		if err != nil {
			return nil, err
		}
		packet, err := query(id, name, t)
		if err != nil {
			return nil, err
		}
		if _, err := pc.WriteTo(packet, to); err != nil {
			return nil, err
		}
		types[id] = t
	}
	// Replies from UDP and from background TCP retries meet here. The
	// channel holds one reply per question, so senders never block.
	replies := make(chan reply, 2*len(types))
	done := make(chan struct{})
	send := func(r reply) {
		select {
		case replies <- r:
		case <-done:
		}
	}
	udpDone := make(chan struct{})
	tcpStarted := map[uint16]bool{}
	go func() {
		defer guard.Recover()
		defer close(udpDone)
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if u, ok := from.(*net.UDPAddr); !ok || u.AddrPort() != server {
				continue
			}
			header, ok := parseHeader(buf[:n], name, types)
			if !ok {
				continue
			}
			if header.Truncated {
				// Ask the same question again over TCP within this attempt,
				// once per question.
				if !tcpStarted[header.ID] {
					tcpStarted[header.ID] = true
					go func(id uint16) {
						defer guard.Recover()
						if r, err := c.exchangeTCP(ctx, server, name, types[id]); err == nil {
							r.id = id
							send(r)
						}
					}(header.ID)
				}
				continue
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil {
				continue
			}
			send(reply{id: m.ID, rcode: m.RCode, answers: m.Answers})
		}
	}()
	defer func() { close(done); _ = pc.Close(); <-udpDone }()
	var ips []netip.Addr
	answered := map[uint16]bool{}
	nxdomain := false
	answeredOne := func(r reply) {
		answered[r.id] = true
		switch r.rcode {
		case dnsmessage.RCodeSuccess:
			ips = append(ips, addresses(r.answers, name, types[r.id])...)
		case dnsmessage.RCodeNameError:
			// NXDOMAIN applies to the name, not to one record type.
			nxdomain = true
		}
	}
	for len(answered) < len(types) {
		select {
		case r := <-replies:
			if answered[r.id] {
				continue
			}
			answeredOne(r)
			if nxdomain {
				return nil, errNoSuchName
			}
		case <-c.closed:
			return nil, ErrClosed
		case <-ctx.Done():
			// Replies already published still count.
			for drained := false; !drained; {
				select {
				case r := <-replies:
					if !answered[r.id] {
						answeredOne(r)
					}
				default:
					drained = true
				}
			}
			if nxdomain {
				return nil, errNoSuchName
			}
			if len(answered) == 0 {
				return nil, errResolve
			}
			return ips, nil
		}
	}
	return ips, nil
}

// parseHeader validates the header and the single question of a reply
// without decoding its records, so a truncated reply can still be matched.
func parseHeader(b []byte, name dnsmessage.Name, types map[uint16]dnsmessage.Type) (dnsmessage.Header, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil || !h.Response || h.OpCode != 0 {
		return h, false
	}
	t, ok := types[h.ID]
	if !ok {
		return h, false
	}
	q, err := p.Question()
	if err != nil || q.Type != t || q.Class != dnsmessage.ClassINET || !strings.EqualFold(q.Name.String(), name.String()) {
		return h, false
	}
	if _, err := p.Question(); !errors.Is(err, dnsmessage.ErrSectionDone) {
		return h, false
	}
	return h, true
}

// exchangeTCP sends one question over a scoped TCP stream.
func (c *Client) exchangeTCP(ctx context.Context, server netip.AddrPort, name dnsmessage.Name, t dnsmessage.Type) (reply, error) {
	conn, err := c.DialStream(ctx, server.String())
	if err != nil {
		return reply{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	id, err := newID(nil)
	if err != nil {
		return reply{}, err
	}
	packet, err := query(id, name, t)
	if err != nil {
		return reply{}, err
	}
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(packet)))
	if _, err := conn.Write(append(framed, packet...)); err != nil {
		return reply{}, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return reply{}, err
	}
	response := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, response); err != nil {
		return reply{}, err
	}
	header, ok := parseHeader(response, name, map[uint16]dnsmessage.Type{id: t})
	if !ok || header.Truncated {
		return reply{}, errResolve
	}
	var m dnsmessage.Message
	if m.Unpack(response) != nil {
		return reply{}, errResolve
	}
	return reply{rcode: m.RCode, answers: m.Answers}, nil
}

// newID returns a random query ID not used by pending.
func newID(pending map[uint16]dnsmessage.Type) (uint16, error) {
	for {
		var b [2]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		if id := binary.BigEndian.Uint16(b[:]); func() bool { _, used := pending[id]; return !used }() {
			return id, nil
		}
	}
}

func query(id uint16, name dnsmessage.Name, t dnsmessage.Type) ([]byte, error) {
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: t, Class: dnsmessage.ClassINET}}}
	return m.Pack()
}

// maxCNAMEChain bounds alias chains, as resolvers do.
const maxCNAMEChain = 8

// addresses takes IN-class A or AAAA records of the queried type for the
// name, following an IN-class CNAME chain from the name regardless of the
// order of records, with cycle detection.
func addresses(answers []dnsmessage.Resource, name dnsmessage.Name, t dnsmessage.Type) []netip.Addr {
	aliases := map[string]string{}
	for _, a := range answers {
		if c, ok := a.Body.(*dnsmessage.CNAMEResource); ok && a.Header.Class == dnsmessage.ClassINET {
			aliases[strings.ToLower(a.Header.Name.String())] = strings.ToLower(c.CNAME.String())
		}
	}
	owners := map[string]bool{}
	owner := strings.ToLower(name.String())
	for i := 0; i <= maxCNAMEChain && !owners[owner]; i++ {
		owners[owner] = true
		next, ok := aliases[owner]
		if !ok {
			break
		}
		owner = next
	}
	var ips []netip.Addr
	for _, a := range answers {
		if a.Header.Class != dnsmessage.ClassINET || a.Header.Type != t || !owners[strings.ToLower(a.Header.Name.String())] {
			continue
		}
		switch body := a.Body.(type) {
		case *dnsmessage.AResource:
			ips = append(ips, netip.AddrFrom4(body.A))
		case *dnsmessage.AAAAResource:
			ips = append(ips, netip.AddrFrom16(body.AAAA))
		}
	}
	return ips
}
