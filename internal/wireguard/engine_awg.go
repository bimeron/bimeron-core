package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// awgTunnel runs amneziawg-go, which also speaks plain WireGuard when no
// AmneziaWG option is set.
type awgTunnel struct {
	dev  *device.Device
	net  *netstack.Net
	peer device.NoisePublicKey
	once sync.Once
}

// Start errors carry no engine text, which may include configuration.
var (
	errEngine = errors.New("WireGuard engine failed")
	// ErrPlatformLimit reports packet sizes beyond this platform's engine
	// buffers (smaller on Windows and iOS than the UDP limit).
	ErrPlatformLimit = errors.New("WireGuard packet sizes exceed this platform's limit")
	// ErrSocket reports that the outbound UDP socket could not be opened.
	ErrSocket = errors.New("WireGuard socket could not be opened")
)

func startAWG(c tunnelConfig) (tunnel, error) {
	for _, size := range c.Sizes {
		if size > device.MaxMessageSize {
			return nil, ErrPlatformLimit
		}
	}
	// DNS servers are not given to the netstack: Bimeron resolves names
	// itself and routes queries by AllowedIPs scope.
	tun, tnet, err := netstack.CreateNetTUN(c.Addresses, nil, c.MTU)
	if err != nil {
		return nil, errEngine
	}
	dev := device.NewDevice(tun, c.Bind, device.NewLogger(device.LogLevelSilent, ""))
	t := &awgTunnel{dev: dev, net: tnet, peer: device.NoisePublicKey(c.PublicKey)}
	if err := dev.IpcSet(c.UAPI); err != nil {
		_ = t.Close()
		if c.Bind.openFailed() {
			return nil, ErrSocket
		}
		return nil, errEngine
	}
	if err := dev.Up(); err != nil {
		_ = t.Close()
		if c.Bind.openFailed() {
			return nil, ErrSocket
		}
		return nil, errEngine
	}
	if c.Bind.openFailed() {
		_ = t.Close()
		return nil, ErrSocket
	}
	return t, nil
}

func (t *awgTunnel) DialTCP(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	return t.net.DialContextTCPAddrPort(ctx, to)
}

func (t *awgTunnel) DialUDP(to netip.AddrPort) (net.Conn, error) {
	return t.net.DialUDPAddrPort(netip.AddrPort{}, to)
}

func (t *awgTunnel) LastHandshake() time.Time {
	if t.dev.LookupPeer(t.peer) == nil {
		return time.Time{}
	}
	// The engine exposes the handshake time through its configuration
	// protocol only; parse the single peer's value.
	text, err := t.dev.IpcGet()
	if err != nil {
		return time.Time{}
	}
	return parseHandshake(text)
}

func (t *awgTunnel) Initiate() {
	if peer := t.dev.LookupPeer(t.peer); peer != nil {
		// Rate-limited by the engine to one initiation per rekey timeout.
		_ = peer.SendHandshakeInitiation(false)
	}
}

func (t *awgTunnel) Close() error {
	t.once.Do(func() { t.dev.Close() })
	return nil
}

// parseHandshake reads the peer's last handshake from engine status text.
// The text holds keys; it is parsed in memory and never logged.
func parseHandshake(text string) time.Time {
	var sec, nsec int64
	for _, line := range strings.Split(text, "\n") {
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(value, 10, 64)
		}
	}
	if sec == 0 && nsec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, nsec)
}
