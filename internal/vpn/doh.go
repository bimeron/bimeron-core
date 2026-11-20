package vpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"time"

	"bimeron/internal/dnsconfig"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

const DoHQueryTimeout = 8 * time.Second
const dnsMediaType = "application/dns-message"
const maxDNSMessage = 65535

type dohAttempt struct {
	url       string
	transport *http.Transport
}

// DoHResolver owns the pools used for encrypted DNS in one upstream generation.
type DoHResolver struct {
	attempts []dohAttempt
}

func NewDoHResolver(dialer transport.StreamDialer, endpoints []dnsconfig.DoHEndpoint, disableIPv6 bool) *DoHResolver {
	if len(endpoints) == 0 {
		return nil
	}
	r := &DoHResolver{}
	for _, endpoint := range endpoints {
		u, _ := url.Parse(endpoint.URL)
		port := u.Port()
		if port == "" {
			port = "443"
		}
		for _, ip := range endpoint.IPs {
			if disableIPv6 && ip.Is6() {
				continue
			}
			target := net.JoinHostPort(ip.String(), port)
			tr := &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					dialCtx, cancel := context.WithTimeout(ctx, dnsconfig.ExchangeTimeout)
					defer cancel()
					return dialer.DialStream(dialCtx, target)
				},
				TLSHandshakeTimeout:    dnsconfig.ExchangeTimeout,
				ForceAttemptHTTP2:      true,
				DisableCompression:     true,
				MaxIdleConnsPerHost:    2,
				IdleConnTimeout:        30 * time.Second,
				MaxResponseHeaderBytes: 8192,
			}
			r.attempts = append(r.attempts, dohAttempt{url: endpoint.URL, transport: tr})
		}
	}
	return r
}

func (r *DoHResolver) Close() {
	if r != nil {
		for _, a := range r.attempts {
			a.transport.CloseIdleConnections()
		}
	}
}

func (r *DoHResolver) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	var request dnsmessage.Message
	if len(query) > maxDNSMessage || request.Unpack(query) != nil || request.Response || len(request.Questions) == 0 {
		return nil, errors.New("invalid DNS query")
	}
	wireQuery := bytes.Clone(query)
	binary.BigEndian.PutUint16(wireQuery, 0)
	clientID := request.ID
	request.ID = 0
	ctx, cancel := context.WithTimeout(ctx, DoHQueryTimeout)
	defer cancel()
	for i, target := range r.attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		deadline, _ := ctx.Deadline()
		budget := min(dnsconfig.ExchangeTimeout, time.Until(deadline)/time.Duration(len(r.attempts)-i))
		attempt, stop := context.WithTimeout(ctx, budget)
		reply := target.exchange(attempt, wireQuery, request)
		stop()
		if reply != nil {
			binary.BigEndian.PutUint16(reply, clientID)
			return reply, nil
		}
	}
	return nil, errors.New("all DoH resolver addresses failed")
}

func (a dohAttempt) exchange(ctx context.Context, query []byte, request dnsmessage.Message) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(query))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", dnsMediaType)
	req.Header.Set("Accept", dnsMediaType)
	resp, err := a.transport.RoundTrip(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != dnsMediaType || resp.StatusCode != http.StatusOK {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	if err != nil || len(data) > maxDNSMessage || !validDNSResponse(data, request) {
		return nil
	}
	var answer dnsmessage.Message
	if answer.Unpack(data) != nil || answer.Truncated {
		return nil
	}
	return data
}
