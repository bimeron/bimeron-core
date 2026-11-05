package androidcore

import (
	"bimeron/core"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SSConfSocketProtector callbacks run synchronously and must return promptly.
// Bind must bind to the exact physical Network captured by the host.
type SSConfSocketProtector interface {
	Protect(fd int) bool
	Bind(fd int) bool
}

// SSConfRequest is a single-use operation independent of Session.
type SSConfRequest struct {
	mu                sync.Mutex
	started, canceled bool
	cancel            context.CancelFunc
	source            string
	network           core.PacketNetwork
	resolve           func(context.Context, string, core.PacketNetwork) ([]byte, error)
}

// SSConfResult holds immutable validated configuration.
type SSConfResult struct{ content []byte }

func (r *SSConfResult) Content() []byte  { return append([]byte(nil), r.content...) }
func (r *SSConfResult) Metadata() string { return fmt.Sprintf("{\"bytes\":%d}", len(r.content)) }

// NewSSConfRequest validates inputs without starting network activity.
func NewSSConfRequest(source, networkID, dns string, sockets SSConfSocketProtector) (*SSConfRequest, error) {
	source = strings.TrimSpace(source)
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "ssconf" || u.Hostname() == "" || u.User != nil {
		return nil, errors.New("invalid ssconf source")
	}
	if sockets == nil || strings.TrimSpace(networkID) == "" {
		return nil, errors.New("physical network and socket callbacks required")
	}
	servers := strings.Split(dns, ",")
	if len(servers) > 4 {
		return nil, errors.New("invalid physical DNS")
	}
	for i, value := range servers {
		ip, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !ip.Is4() {
			return nil, errors.New("invalid physical DNS")
		}
		servers[i] = ip.String()
	}
	d := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		var failure error
		err := raw.Control(func(fd uintptr) {
			if !sockets.Protect(int(fd)) {
				failure = errors.New("socket protection failed")
				return
			}
			if !sockets.Bind(int(fd)) {
				failure = errors.New("socket binding failed")
			}
		})
		if err != nil {
			return errors.New("socket control failed")
		}
		return failure
	}}
	return &SSConfRequest{source: source, network: core.PacketNetwork{Identity: networkID, DNS: servers, Dialer: d}}, nil
}

func (r *SSConfRequest) Resolve() (*SSConfResult, error) {
	r.mu.Lock()
	if r.started || r.canceled {
		r.mu.Unlock()
		return nil, errors.New("ssconf request unavailable")
	}
	r.started = true
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	r.cancel = cancel
	r.mu.Unlock()
	defer cancel()
	resolve := r.resolve
	if resolve == nil {
		resolve = core.ResolveSSConf
	}
	b, err := resolve(ctx, r.source, r.network)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.canceled || ctx.Err() != nil {
		return nil, errors.New("ssconf request canceled or timed out")
	}
	if err != nil {
		return nil, errors.New("ssconf resolution failed")
	}
	return &SSConfResult{content: append([]byte(nil), b...)}, nil
}

func (r *SSConfRequest) Cancel() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.canceled = true
	if r.cancel != nil {
		r.cancel()
	}
}
