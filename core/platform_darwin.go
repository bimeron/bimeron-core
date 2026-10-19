//go:build darwin

package core

import (
	"context"
	"encoding/json"
	"errors"
	stack "github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"net"
	"bimeron/internal/macnet"
	"bimeron/internal/unixutil"
	"time"
)

type darwinPlatform struct {
	killSwitch  bool
	manager     *macnet.Manager
	tunnelName  string
	tunnelIndex int
}

func newPlatform(c SessionConfig) platform {
	return &darwinPlatform{killSwitch: c.KillSwitch, manager: macnet.NewManager()}
}
func (p *darwinPlatform) Acquire(ctx context.Context) (func(), error) {
	// Never silently weaken a profile requesting protection this backend cannot provide.
	if p.killSwitch {
		return nil, fault("kill_switch_unsupported_on_macos", false)
	}
	if err := macnet.Requirements(); err != nil {
		return nil, fault(err.Error(), false)
	}
	release, err := unixutil.Lock("vpn.lock")
	if err != nil {
		return nil, fault("session_lock_failed", false)
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := p.manager.Recover(cleanupCtx, false); err != nil {
		release()
		return nil, fault("macos_recovery_failed_run_recover", false)
	}
	return release, nil
}
func (p *darwinPlatform) Inspect(ctx context.Context, _ string, startup bool) (networkPath, error) {
	if startup {
		if err := p.manager.Preflight(ctx); err != nil {
			return networkPath{}, fault(err.Error(), false)
		}
	} else {
		iface, err := net.InterfaceByName(p.tunnelName)
		if err != nil || iface.Index != p.tunnelIndex || iface.Flags&net.FlagUp == 0 {
			return networkPath{}, fault("tunnel_adapter_lost", false)
		}
		if err := p.manager.EnsureDNS(ctx); err != nil {
			return networkPath{}, fault(err.Error(), !errors.Is(err, macnet.ErrDNSConflict))
		}
	}
	s, err := p.manager.Observe(ctx)
	if err != nil {
		return networkPath{}, fault(err.Error(), errors.Is(err, macnet.ErrNetworkUnavailable))
	}
	if !startup {
		if err := p.manager.EnsureBypass(ctx, s.Device, s.Gateway); err != nil {
			return networkPath{}, fault("macos_bypass_route_setup_failed", true)
		}
	}
	identity, _ := json.Marshal(s)
	return networkPath{
		identity: string(identity),
		dns:      s.DNS,
		dialer:   net.Dialer{Timeout: 15 * time.Second, Control: macnet.BoundDialer(s.Index)},
		refresh:  p.manager.RefreshDNS,
	}, nil
}
func (p *darwinPlatform) Open(ctx context.Context, c SessionConfig, h *flowRouter, report func(string, string)) (result link, err error) {
	owned := &cleanup{}
	defer func() {
		if err != nil {
			if e := owned.Close(); e != nil {
				err = e
			}
		}
	}()
	report("adapter_create", "Creating macOS utun adapter")
	// macOS assigns utunN; the profile Name remains a logical label.
	d, err := tun.Open("utun", uint32(c.MTU))
	if err != nil {
		return nil, fault("adapter_create_failed", false)
	}
	owned.add(func() error { d.Close(); return nil })
	iface, err := net.InterfaceByName(d.Name())
	if err != nil {
		return nil, fault("adapter_lookup_failed", false)
	}
	p.tunnelName, p.tunnelIndex = d.Name(), iface.Index
	s, err := stack.CreateStack(&stack.Config{LinkEndpoint: d, TransportHandler: h})
	if err != nil {
		return nil, fault("packet_stack_failed", false)
	}
	owned.add(func() error { s.Close(); return nil })
	owned.add(func() error { h.Close(); return nil })
	owned.add(func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		return p.manager.Recover(cleanupCtx, false)
	})
	report("network_setup", "Configuring macOS routes and tunnel DNS")
	if err := p.manager.Configure(ctx, d.Name(), c.MTU); err != nil {
		if errors.Is(err, macnet.ErrDNSConflict) {
			return nil, fault(err.Error(), false)
		}
		return nil, fault("macos_network_setup_failed: "+err.Error(), false)
	}
	return owned, nil
}
