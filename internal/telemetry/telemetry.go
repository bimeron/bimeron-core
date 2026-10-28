// Package telemetry provides bounded, secret-free session counters shared by
// the VPN packet handler and the local SOCKS server. Counter methods work on a
// nil receiver, so a missing Stats pointer is always valid and costs nothing.
package telemetry

import (
	"sync/atomic"

	"bimeron/internal/routing"
)

type Counters struct {
	TCPTotal     atomic.Int64
	TCPActive    atomic.Int64
	TCPFailed    atomic.Int64
	UDPTotal     atomic.Int64
	UDPActive    atomic.Int64
	UDPFailed    atomic.Int64
	DNSQueries   atomic.Int64
	DNSFailed    atomic.Int64
	BytesUp      atomic.Int64
	BytesDown    atomic.Int64
	RoutedProxy  atomic.Int64
	RoutedDirect atomic.Int64
	RoutedBlock  atomic.Int64
}

// Snapshot is a detached point-in-time copy safe for JSON transport. Byte and
// flow counts never contain addresses, credentials or destinations.
type Snapshot struct {
	Unavailable  bool  `json:"unavailable,omitempty"`
	TCPTotal     int64 `json:"tcp_total"`
	TCPActive    int64 `json:"tcp_active"`
	TCPFailed    int64 `json:"tcp_failed"`
	UDPTotal     int64 `json:"udp_total"`
	UDPActive    int64 `json:"udp_active"`
	UDPFailed    int64 `json:"udp_failed"`
	DNSQueries   int64 `json:"dns_queries"`
	DNSFailed    int64 `json:"dns_failed"`
	BytesUp      int64 `json:"bytes_up"`
	BytesDown    int64 `json:"bytes_down"`
	RoutedProxy  int64 `json:"routed_proxy"`
	RoutedDirect int64 `json:"routed_direct"`
	RoutedBlock  int64 `json:"routed_block"`
}

func (c *Counters) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	return Snapshot{
		TCPTotal:     c.TCPTotal.Load(),
		TCPActive:    c.TCPActive.Load(),
		TCPFailed:    c.TCPFailed.Load(),
		UDPTotal:     c.UDPTotal.Load(),
		UDPActive:    c.UDPActive.Load(),
		UDPFailed:    c.UDPFailed.Load(),
		DNSQueries:   c.DNSQueries.Load(),
		DNSFailed:    c.DNSFailed.Load(),
		BytesUp:      c.BytesUp.Load(),
		BytesDown:    c.BytesDown.Load(),
		RoutedProxy:  c.RoutedProxy.Load(),
		RoutedDirect: c.RoutedDirect.Load(),
		RoutedBlock:  c.RoutedBlock.Load(),
	}
}

func (c *Counters) AttemptTCP() {
	if c == nil {
		return
	}
	c.TCPTotal.Add(1)
}
func (c *Counters) EstablishTCP() {
	if c == nil {
		return
	}
	c.TCPActive.Add(1)
}
func (c *Counters) EndTCP() {
	if c == nil {
		return
	}
	c.TCPActive.Add(-1)
}
func (c *Counters) FailTCP() {
	if c == nil {
		return
	}
	c.TCPFailed.Add(1)
}
func (c *Counters) AttemptUDP() {
	if c == nil {
		return
	}
	c.UDPTotal.Add(1)
}
func (c *Counters) EstablishUDP() {
	if c == nil {
		return
	}
	c.UDPActive.Add(1)
}
func (c *Counters) EndUDP() {
	if c == nil {
		return
	}
	c.UDPActive.Add(-1)
}
func (c *Counters) FailUDP() {
	if c == nil {
		return
	}
	c.UDPFailed.Add(1)
}
func (c *Counters) DNSQuery() {
	if c == nil {
		return
	}
	c.DNSQueries.Add(1)
}
func (c *Counters) DNSFailure() {
	if c == nil {
		return
	}
	c.DNSFailed.Add(1)
}
func (c *Counters) Sent(n int64) {
	if c == nil || n <= 0 {
		return
	}
	c.BytesUp.Add(n)
}
func (c *Counters) Received(n int64) {
	if c == nil || n <= 0 {
		return
	}
	c.BytesDown.Add(n)
}
func (c *Counters) RouteDecided(a routing.Action) {
	if c == nil {
		return
	}
	switch a {
	case routing.Proxy:
		c.RoutedProxy.Add(1)
	case routing.Direct:
		c.RoutedDirect.Add(1)
	case routing.Block:
		c.RoutedBlock.Add(1)
	}
}
