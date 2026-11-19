// Package wireguard runs a userspace WireGuard or AmneziaWG client over a
// netstack and exposes it as an Outline SDK stream dialer and packet listener.
// Secrets never reach logs: the engine logger is silent and errors are
// replaced by fixed messages.
package wireguard

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// tunnel is the small surface Bimeron needs from a WireGuard engine. A
// different engine, such as upstream wireguard-go for plain WireGuard, only
// has to provide another implementation of this interface.
type tunnel interface {
	// DialTCP opens a TCP connection inside the tunnel.
	DialTCP(ctx context.Context, to netip.AddrPort) (net.Conn, error)
	// DialUDP opens a UDP socket inside the tunnel connected to one
	// destination.
	DialUDP(to netip.AddrPort) (net.Conn, error)
	// LastHandshake reports the last completed handshake, zero if none.
	LastHandshake() time.Time
	// Initiate asks the engine to send a keepalive, which starts a
	// handshake when no session key exists.
	Initiate()
	// Close stops the device and releases its socket and goroutines. It is
	// safe to call more than once.
	Close() error
}

// tunnelConfig is everything an engine needs to start.
type tunnelConfig struct {
	// Addresses are the tunnel interface addresses.
	Addresses []netip.Addr
	MTU       int
	// UAPI is the engine configuration. It holds secrets.
	UAPI string
	// PublicKey is the peer, used to query handshake state.
	PublicKey [32]byte
	// Bind sends and receives the encrypted datagrams.
	Bind *Bind
}

// engine starts a tunnel. Tests replace it to inject failures.
type engine func(tunnelConfig) (tunnel, error)
