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
		case err == nil && len(ips) > 0:
			return ips, nil
		}
	}
	return nil, errResolve
}

// question is one outstanding query of an exchange.
type question struct {
	t        dnsmessage.Type
	answered bool
}

// exchange asks one resolver for A and AAAA records over UDP, retrying a
// truncated question over TCP. It returns the addresses of every question
// that was answered; it fails only when none was.
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
	pending := map[uint16]*question{}
	for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		id, err := newID(pending)
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
		pending[id] = &question{t: t}
	}
	var ips []netip.Addr
	answered, nxdomain := 0, false
	buf := make([]byte, 4096)
	for answered < len(pending) {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		if u, ok := from.(*net.UDPAddr); !ok || u.AddrPort() != server {
			continue
		}
		var m dnsmessage.Message
		if m.Unpack(buf[:n]) != nil {
			continue
		}
		q := pending[m.ID]
		if q == nil || q.answered || !validResponse(m, name, q.t) {
			continue
		}
		if m.Truncated {
			// Ask the same question again over TCP within this attempt.
			answers, rcode, err := c.exchangeTCP(ctx, server, name, q.t)
			if err != nil {
				continue
			}
			m.RCode, m.Answers = rcode, answers
		}
		q.answered = true
		answered++
		switch m.RCode {
		case dnsmessage.RCodeSuccess:
			ips = append(ips, addresses(m.Answers, name, q.t)...)
		case dnsmessage.RCodeNameError:
			nxdomain = true
		}
	}
	if nxdomain {
		// NXDOMAIN applies to the name, not to one record type.
		return nil, errNoSuchName
	}
	if answered == 0 {
		return nil, errResolve
	}
	return ips, nil
}

// exchangeTCP sends one question over a scoped TCP stream.
func (c *Client) exchangeTCP(ctx context.Context, server netip.AddrPort, name dnsmessage.Name, t dnsmessage.Type) ([]dnsmessage.Resource, dnsmessage.RCode, error) {
	conn, err := c.DialStream(ctx, server.String())
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	id, err := newID(nil)
	if err != nil {
		return nil, 0, err
	}
	packet, err := query(id, name, t)
	if err != nil {
		return nil, 0, err
	}
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(packet)))
	if _, err := conn.Write(append(framed, packet...)); err != nil {
		return nil, 0, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, 0, err
	}
	response := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, 0, err
	}
	var m dnsmessage.Message
	if m.Unpack(response) != nil || m.ID != id || !validResponse(m, name, t) || m.Truncated {
		return nil, 0, errResolve
	}
	return m.Answers, m.RCode, nil
}

// newID returns a random query ID not used by pending.
func newID(pending map[uint16]*question) (uint16, error) {
	for {
		var b [2]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		if id := binary.BigEndian.Uint16(b[:]); pending[id] == nil {
			return id, nil
		}
	}
}

func query(id uint16, name dnsmessage.Name, t dnsmessage.Type) ([]byte, error) {
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: t, Class: dnsmessage.ClassINET}}}
	return m.Pack()
}

// validResponse checks that m answers exactly the question asked.
func validResponse(m dnsmessage.Message, name dnsmessage.Name, t dnsmessage.Type) bool {
	if !m.Response || m.OpCode != 0 || len(m.Questions) != 1 {
		return false
	}
	q := m.Questions[0]
	return q.Type == t && q.Class == dnsmessage.ClassINET && strings.EqualFold(q.Name.String(), name.String())
}

// addresses takes A or AAAA records of the queried type. Records for other
// owners are accepted only as the target of a CNAME chain from the name.
func addresses(answers []dnsmessage.Resource, name dnsmessage.Name, t dnsmessage.Type) []netip.Addr {
	owners := map[string]bool{strings.ToLower(name.String()): true}
	for _, a := range answers {
		if c, ok := a.Body.(*dnsmessage.CNAMEResource); ok && owners[strings.ToLower(a.Header.Name.String())] {
			owners[strings.ToLower(c.CNAME.String())] = true
		}
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
