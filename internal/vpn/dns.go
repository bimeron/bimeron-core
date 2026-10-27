package vpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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

type dnsAttemptError struct {
	stage string
	err   error
}

func (e dnsAttemptError) Error() string { return e.stage + ": " + e.err.Error() }
func (e dnsAttemptError) Unwrap() error { return e.err }

// Keep transport errors out of the journal: they may contain destinations or profile data.
func dnsAttemptDetail(err error) string {
	var attempt dnsAttemptError
	if !errors.As(err, &attempt) {
		return "transport error"
	}
	var status interface{ HTTPStatusCode() int }
	if errors.As(err, &status) {
		return fmt.Sprintf("%s upstream HTTP %d", attempt.stage, status.HTTPStatusCode())
	}
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return attempt.stage + " timeout"
	case errors.Is(err, net.ErrClosed):
		return attempt.stage + " connection closed"
	case errors.Is(err, io.EOF):
		return attempt.stage + " end of stream"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return attempt.stage + " truncated stream"
	case err.Error() == "UDP read: invalid XUDP metadata", err.Error() == "UDP read: invalid XUDP command", err.Error() == "UDP read: invalid XUDP payload":
		return err.Error()
	default:
		return attempt.stage + " failed"
	}
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
	var failures []string
	for i, server := range r.Servers {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		attempt, cancel := context.WithTimeout(ctx, timeout)
		response, err := r.exchangeOne(attempt, query, request, server, tcp)
		if errors.Is(attempt.Err(), context.DeadlineExceeded) {
			var staged dnsAttemptError
			if errors.As(err, &staged) {
				err = dnsAttemptError{staged.stage, context.DeadlineExceeded}
			}
		}
		cancel()
		if err == nil {
			return response, nil
		}
		failures = append(failures, fmt.Sprintf("resolver %d: %s", i+1, dnsAttemptDetail(err)))
	}
	return nil, fmt.Errorf("all DNS resolvers failed (%s)", strings.Join(failures, "; "))
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
			return nil, dnsAttemptError{"TCP dial", err}
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { _ = c.Close() })
		defer stop()
		_ = c.SetDeadline(deadline)
		frame := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(frame, uint16(len(query)))
		copy(frame[2:], query)
		if _, err := io.Copy(c, bytes.NewReader(frame)); err != nil {
			return nil, dnsAttemptError{"TCP write", err}
		}
		var size [2]byte
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return nil, dnsAttemptError{"TCP read", err}
		}
		b := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, err := io.ReadFull(c, b); err != nil {
			return nil, dnsAttemptError{"TCP read", err}
		}
		if !validDNSResponse(b, request) {
			return nil, dnsAttemptError{"TCP response", errors.New("unusable answer")}
		}
		return b, nil
	}
	if r.UDP == nil {
		return nil, fmt.Errorf("DNS UDP transport unavailable")
	}
	c, err := r.UDP.ListenPacket(ctx)
	if err != nil {
		return nil, dnsAttemptError{"UDP open", err}
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	_ = c.SetDeadline(deadline)
	destination := &net.UDPAddr{IP: net.ParseIP(server), Port: 53}
	if _, err := c.WriteTo(query, destination); err != nil {
		return nil, dnsAttemptError{"UDP write", err}
	}
	b := make([]byte, 16*1024)
	for {
		n, source, err := c.ReadFrom(b)
		if err != nil {
			return nil, dnsAttemptError{"UDP read", err}
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
			return nil, dnsAttemptError{"UDP response", errors.New("unusable answer")}
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
			resolver := h.resolver()
			answer, err := resolver.Exchange(h.ctx, query, false)
			if err != nil {
				udpErr := err
				answer, err = resolver.Exchange(h.ctx, query, true)
				if err != nil {
					err = fmt.Errorf("UDP: %v; TCP: %w", udpErr, err)
				} else {
					h.report("dns_tcp_fallback", "DNS resolved over TCP after UDP failed")
				}
			}
			if err != nil {
				h.Stats.DNSFailure()
				answer = dnsFailure(query)
				h.report("dns_failed", err.Error())
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
				h.report("dns_failed", err.Error())
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
