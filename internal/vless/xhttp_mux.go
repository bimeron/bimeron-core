package vless

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"bimeron/internal/accesskey"
	"golang.org/x/net/http2"
)

type xhttpMuxConn struct {
	conn             *http2.ClientConn
	active, requests int
	created          time.Time
}

type xhttpMuxPool struct {
	mu      sync.Mutex
	h2      http2.Transport
	dial    func(context.Context) (net.Conn, error)
	config  accesskey.XHTTPXmux
	conns   []*xhttpMuxConn
	opening int
	closed  bool
	wake    chan struct{}
}

func newXHTTPMuxPool(dial func(context.Context) (net.Conn, error), config *accesskey.XHTTPXmux) *xhttpMuxPool {
	selected := *config
	for _, r := range []*accesskey.XHTTPRange{&selected.MaxConcurrency, &selected.MaxConnections, &selected.CMaxReuseTimes, &selected.HMaxRequestTimes, &selected.HMaxReusableSecs} {
		if r.To > 0 {
			n := xhttpRangeValue(*r, r.From)
			r.From, r.To = n, n
		}
	}
	return &xhttpMuxPool{dial: dial, config: selected, wake: make(chan struct{})}
}

func (p *xhttpMuxPool) signal() { close(p.wake); p.wake = make(chan struct{}) }

func (p *xhttpMuxPool) RoundTrip(req *http.Request) (*http.Response, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		var selected *xhttpMuxConn
		retained := p.conns[:0]
		for _, c := range p.conns {
			expired := !c.conn.CanTakeNewRequest() || p.config.HMaxRequestTimes.From > 0 && c.requests >= p.config.HMaxRequestTimes.From || p.config.CMaxReuseTimes.From > 0 && c.requests >= p.config.CMaxReuseTimes.From || p.config.HMaxReusableSecs.From > 0 && time.Since(c.created) >= time.Duration(p.config.HMaxReusableSecs.From)*time.Second
			if expired && c.active == 0 {
				_ = c.conn.Close()
				continue
			}
			retained = append(retained, c)
			if expired {
				continue
			}
			if limit := p.config.MaxConcurrency.From; limit > 0 && c.active >= limit {
				continue
			}
			if limit := p.config.HMaxRequestTimes.From; limit > 0 && c.requests >= limit {
				continue
			}
			if limit := p.config.CMaxReuseTimes.From; limit > 0 && c.requests >= limit {
				continue
			}
			if limit := p.config.HMaxReusableSecs.From; limit > 0 && time.Since(c.created) >= time.Duration(limit)*time.Second {
				continue
			}
			if selected == nil {
				selected = c
			}
		}
		p.conns = retained
		if selected != nil {
			selected.active++
			selected.requests++
			p.mu.Unlock()
			resp, err := selected.conn.RoundTrip(req)
			if err != nil {
				p.release(selected)
				return nil, err
			}
			resp.Body = &xhttpMuxBody{ReadCloser: resp.Body, release: func() { p.release(selected) }}
			return resp, nil
		}
		maxConnections := p.config.MaxConnections.From
		if maxConnections == 0 || len(p.conns)+p.opening < maxConnections {
			p.opening++
			p.mu.Unlock()
			raw, err := p.dial(req.Context())
			var h2conn *http2.ClientConn
			if err == nil {
				h2conn, err = p.h2.NewClientConn(raw)
			}
			if err != nil && raw != nil {
				_ = raw.Close()
			}
			p.mu.Lock()
			p.opening--
			if err == nil && !p.closed {
				p.conns = append(p.conns, &xhttpMuxConn{conn: h2conn, created: time.Now()})
			} else if h2conn != nil {
				_ = h2conn.Close()
			}
			p.signal()
			p.mu.Unlock()
			if err != nil {
				return nil, fmt.Errorf("XHTTP HTTP/2 connection failed: %w", err)
			}
			continue
		}
		wake := p.wake
		p.mu.Unlock()
		select {
		case <-wake:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
}

func (p *xhttpMuxPool) release(c *xhttpMuxConn) {
	p.mu.Lock()
	c.active--
	p.signal()
	p.mu.Unlock()
}

func (p *xhttpMuxPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	conns := p.conns
	p.conns = nil
	p.signal()
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.conn.Close()
	}
}

type xhttpMuxBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *xhttpMuxBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.release)
	}
	return n, err
}
func (b *xhttpMuxBody) Close() error { err := b.ReadCloser.Close(); b.once.Do(b.release); return err }
