package vpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

// DNSResolver retries each DNS request in configured order through the upstream proxy.
// A negative answer (NXDOMAIN) is definitive, not a reason to change resolver.
type DNSResolver struct {
	DisableIPv6 bool
	Servers     []string
	TCP         transport.StreamDialer
	UDP         transport.PacketListener
	Timeout     time.Duration
}

func (r DNSResolver) Exchange(ctx context.Context, query []byte, tcp bool) ([]byte, error) {
	var request dnsmessage.Message
	if err := request.Unpack(query); err != nil || request.Response || len(request.Questions) == 0 {
		return nil, fmt.Errorf("invalid DNS query")
	}
	if r.DisableIPv6 {
		for _, question := range request.Questions {
			if question.Type == dnsmessage.TypeAAAA {
				answer := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, OpCode: request.OpCode, RecursionDesired: request.RecursionDesired, RecursionAvailable: true}, Questions: request.Questions}
				return answer.Pack()
			}
		}
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	for _, server := range r.Servers {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		attempt, cancel := context.WithTimeout(ctx, timeout)
		response, err := r.exchangeOne(attempt, query, request, server, tcp)
		cancel()
		if err == nil {
			return response, nil
		}
	}
	return nil, fmt.Errorf("all DNS resolvers failed")
}
func validDNSResponse(b []byte, request dnsmessage.Message) bool {
	var p dnsmessage.Parser
	header, err := p.Start(b)
	if err != nil || !header.Response || header.ID != request.ID || header.OpCode != request.OpCode {
		return false
	}
	questions, err := p.AllQuestions()
	if err != nil || len(questions) != len(request.Questions) {
		return false
	}
	for i, q := range questions {
		expected := request.Questions[i]
		if q.Type != expected.Type || q.Class != expected.Class || !strings.EqualFold(q.Name.String(), expected.Name.String()) {
			return false
		}
	}
	return header.RCode == dnsmessage.RCodeSuccess || header.RCode == dnsmessage.RCodeNameError
}
func (r DNSResolver) exchangeOne(ctx context.Context, query []byte, request dnsmessage.Message, server string, tcp bool) ([]byte, error) {
	address := net.JoinHostPort(server, "53")
	deadline, _ := ctx.Deadline()
	if tcp {
		if r.TCP == nil {
			return nil, fmt.Errorf("DNS TCP transport unavailable")
		}
		c, err := r.TCP.DialStream(ctx, address)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { _ = c.Close() })
		defer stop()
		_ = c.SetDeadline(deadline)
		frame := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(frame, uint16(len(query)))
		copy(frame[2:], query)
		if _, err := io.Copy(c, bytes.NewReader(frame)); err != nil {
			return nil, err
		}
		var size [2]byte
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return nil, err
		}
		b := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, err := io.ReadFull(c, b); err != nil {
			return nil, err
		}
		if !validDNSResponse(b, request) {
			return nil, fmt.Errorf("unusable DNS TCP answer")
		}
		return b, nil
	}
	if r.UDP == nil {
		return nil, fmt.Errorf("DNS UDP transport unavailable")
	}
	c, err := r.UDP.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	_ = c.SetDeadline(deadline)
	destination := &net.UDPAddr{IP: net.ParseIP(server), Port: 53}
	if _, err := c.WriteTo(query, destination); err != nil {
		return nil, err
	}
	b := make([]byte, 16*1024)
	for {
		n, source, err := c.ReadFrom(b)
		if err != nil {
			return nil, err
		}
		if source == nil || source.String() != destination.String() {
			continue
		}
		// A matching but unusable response (e.g. SERVFAIL/REFUSED) triggers fallback.
		var p dnsmessage.Parser
		header, err := p.Start(b[:n])
		if err != nil || header.ID != request.ID || !header.Response {
			continue
		}
		if !validDNSResponse(b[:n], request) {
			return nil, fmt.Errorf("unusable DNS UDP answer")
		}
		return append([]byte(nil), b[:n]...), nil
	}
}
func dnsFailure(query []byte) []byte {
	var q dnsmessage.Message
	if q.Unpack(query) != nil || q.Response {
		return nil
	}
	answer := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, OpCode: q.OpCode, RecursionDesired: q.RecursionDesired, RCode: dnsmessage.RCodeServerFailure}, Questions: q.Questions}
	b, _ := answer.Pack()
	return b
}
func (h *Handler) resolver() DNSResolver {
	return DNSResolver{Servers: h.DNS, TCP: h.TCP, UDP: h.UDP, DisableIPv6: h.DisableIPv6}
}
func (h *Handler) handleDNSUDP(c adapter.UDPConn) {
	h.start(c, func() {
		buffer := make([]byte, 16*1024)
		for {
			_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, _, err := c.ReadFrom(buffer)
			if err != nil {
				return
			}
			h.Stats.Sent(int64(n))
			query := buffer[:n]
			h.Stats.DNSQuery()
			answer, err := h.resolver().Exchange(h.ctx, query, false)
			if err != nil {
				h.Stats.DNSFailure()
				answer = dnsFailure(query)
				h.report("dns_failed", "All configured DNS resolvers failed")
			} else {
				h.Metadata.Observe(query, answer, h.Policy)
			}
			if len(answer) == 0 {
				continue
			}
			h.Stats.Received(int64(len(answer)))
			if _, err = c.Write(answer); err != nil {
				return
			}
		}
	})
}
func (h *Handler) handleDNSTCP(c adapter.TCPConn) {
	h.start(c, func() {
		for {
			_ = c.SetDeadline(time.Now().Add(60 * time.Second))
			var size [2]byte
			if _, err := io.ReadFull(c, size[:]); err != nil {
				return
			}
			query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
			if _, err := io.ReadFull(c, query); err != nil {
				return
			}
			h.Stats.Sent(int64(len(query)))
			h.Stats.DNSQuery()
			answer, err := h.resolver().Exchange(h.ctx, query, true)
			if err != nil {
				h.Stats.DNSFailure()
				answer = dnsFailure(query)
				h.report("dns_failed", "All configured DNS resolvers failed")
			} else {
				h.Metadata.Observe(query, answer, h.Policy)
			}
			if len(answer) == 0 {
				return
			}
			h.Stats.Received(int64(len(answer)))
			frame := make([]byte, 2+len(answer))
			binary.BigEndian.PutUint16(frame, uint16(len(answer)))
			copy(frame[2:], answer)
			if _, err := io.Copy(c, bytes.NewReader(frame)); err != nil {
				return
			}
		}
	})
}
