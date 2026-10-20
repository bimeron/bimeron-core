//go:build linux

package core

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"bimeron/internal/linuxnet"
	stack "github.com/xjasonlyu/tun2socks/v2/core"
)

type linuxPlatform struct {
	killSwitch bool
	manager    *linuxnet.Manager
}

func newPlatform(c SessionConfig) platform {
	return &linuxPlatform{killSwitch: c.KillSwitch, manager: linuxnet.NewManager()}
}
func (p *linuxPlatform) Acquire(ctx context.Context) (func(), error) {
	if err := linuxnet.Requirements(p.killSwitch); err != nil {
		return nil, fault(err.Error(), false)
	}
	release, err := linuxnet.Lock("vpn.lock")
	if err != nil {
		return nil, fault("session_lock_failed", false)
	}
	state, err := p.manager.Load()
	if err == nil && state != nil && state.Guard && !p.killSwitch {
		err = fault("kill_switch_pending_run_recover", false)
	}
	if err == nil {
		err = p.manager.Recover(ctx, p.killSwitch)
	}
	if err != nil {
		release()
		return nil, fault("linux_recovery_failed: "+err.Error(), false)
	}
	return release, nil
}
func (p *linuxPlatform) Inspect(ctx context.Context, name string, startup bool) (networkPath, error) {
	s, err := p.manager.Observe(ctx, name, startup)
	if err != nil {
		return networkPath{}, fault(err.Error(), errors.Is(err, linuxnet.ErrNetworkUnavailable))
	}
	identity, _ := json.Marshal(s)
	return networkPath{identity: string(identity), dns: s.DNS, dialer: net.Dialer{Timeout: 15 * time.Second, Control: linuxnet.BoundDialer(s.Device)}}, nil
}
func (p *linuxPlatform) Open(ctx context.Context, c SessionConfig, h *flowRouter, report func(string, string)) (result link, err error) {
	owned := &cleanup{}
	defer func() {
		if err != nil {
			if e := owned.Close(); e != nil {
				err = e
			}
		}
	}()
	report("adapter_create", "Creating Linux TUN adapter")
	d, err := linuxnet.OpenTUN(c.Name, uint32(c.MTU))
	if err != nil {
		return nil, fault("adapter_create_failed", false)
	}
	owned.add(func() error { d.Close(); return nil })
	s, err := stack.CreateStack(&stack.Config{LinkEndpoint: d, TransportHandler: h})
	if err != nil {
		return nil, fault("packet_stack_failed", false)
	}
	owned.add(func() error { s.Destroy(); return nil })
	owned.add(func() error { h.Close(); return nil })
	owned.add(func() error {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		return p.manager.Recover(cleanCtx, false)
	})
	report("network_setup", "Configuring Linux policy routes and tunnel DNS")
	if err = p.manager.Configure(ctx, d.Name(), c.MTU, c.Policy, c.DisableIPv6, c.KillSwitch); err != nil {
		return nil, fault("linux_network_setup_failed: "+err.Error(), false)
	}
	if c.KillSwitch {
		report("kill_switch_active", "nftables kill switch active; protection survives process termination")
	}
	return owned, nil
}
