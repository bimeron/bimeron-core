//go:build linux

package core

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"bimeron/internal/linuxnet"
	stack "github.com/xjasonlyu/tun2socks/v2/core"
)

type linuxPlatform struct {
	killSwitch  bool
	name        string
	policy      *Policy
	disableIPv6 bool
	manager     *linuxnet.Manager
	// protected is set while Acquire's kill switch belongs to this run;
	// retain makes the next release keep it installed.
	protected, retain atomic.Bool
	// releaseErr records a failed removal; it is read after release returns.
	releaseErr error
}

var _ protectedPlatform = (*linuxPlatform)(nil)

func newPlatform(c SessionConfig) platform {
	return &linuxPlatform{killSwitch: c.KillSwitch, name: c.Name, policy: c.Policy, disableIPv6: c.DisableIPv6, manager: linuxnet.NewManager()}
}
func (p *linuxPlatform) Acquire(ctx context.Context) (func(), error) {
	if err := linuxnet.Requirements(p.killSwitch); err != nil {
		return nil, requirementsFault(err)
	}
	release, err := linuxnet.LockSession()
	if err != nil {
		return nil, fault("session_lock_failed", false)
	}
	return p.acquire(ctx, release)
}

// acquire runs under the session lock: it recovers a crashed session and, with
// the kill switch, installs protection before any session traffic. The
// returned release removes that protection unless RetainProtection was called,
// then unlocks.
func (p *linuxPlatform) acquire(ctx context.Context, unlock func()) (func(), error) {
	p.protected.Store(false)
	p.retain.Store(false)
	p.releaseErr = nil
	state, err := p.manager.Load()
	if err == nil && state != nil && state.Guard && !p.killSwitch {
		err = fault("kill_switch_pending_run_recover", false)
	}
	if err == nil {
		err = p.manager.Recover(ctx, p.killSwitch)
	}
	if err != nil {
		unlock()
		return nil, codeFault(err, "linux_recovery_failed", false)
	}
	if p.killSwitch {
		if !linuxnet.ValidName(p.name) {
			// Same code Inspect reports for this name without the kill switch.
			unlock()
			return nil, fault("network_inspect_failed", false)
		}
		// The guard accepts the tunnel by name. A foreign interface with that
		// name would be exempted, so refuse before installing anything.
		if _, err := net.InterfaceByName(p.name); err == nil {
			unlock()
			return nil, fault("adapter_name_in_use", false)
		}
		// A failed install keeps whatever protection and journal exist.
		if err := p.manager.Guard(ctx, p.name, p.policy, p.disableIPv6); err != nil {
			unlock()
			return nil, codeFault(err, "kill_switch_arm_failed_run_recover", false)
		}
		p.protected.Store(true)
	}
	return func() {
		if p.protected.Swap(false) {
			cleanCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			// A failed removal keeps protection installed: fail closed, and
			// reported to the engine as a cleanup failure.
			if err := p.manager.Recover(cleanCtx, p.retain.Load()); err != nil && !p.retain.Load() {
				p.releaseErr = err
			}
			cancel()
		}
		unlock()
	}, nil
}

// Protected reports whether Acquire installed the run's kill switch.
func (p *linuxPlatform) Protected() bool { return p.killSwitch && p.protected.Load() }

// RetainProtection makes the pending release keep the kill switch installed.
func (p *linuxPlatform) RetainProtection() { p.retain.Store(true) }

// ReleaseError reports whether the last release failed to remove protection.
func (p *linuxPlatform) ReleaseError() error { return p.releaseErr }

func (p *linuxPlatform) Inspect(ctx context.Context, name string, startup bool) (networkPath, error) {
	s, err := p.manager.Observe(ctx, name, startup)
	if err != nil {
		if errors.Is(err, linuxnet.ErrTunnelNameInUse) {
			return networkPath{}, fault("adapter_name_in_use", false)
		}
		return networkPath{}, codeFault(err, "network_inspect_failed", errors.Is(err, linuxnet.ErrNetworkUnavailable))
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
	// The guard exempts the tunnel by name: never create the TUN when another
	// interface took that name after Acquire.
	if p.killSwitch {
		if _, err := net.InterfaceByName(c.Name); err == nil {
			return nil, fault("adapter_name_in_use", false)
		}
	}
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
		// The kill switch belongs to the run: only Acquire's release removes it.
		return p.manager.Recover(cleanCtx, p.killSwitch)
	})
	report("network_setup", "Configuring Linux policy routes and tunnel DNS")
	if err = p.manager.Configure(ctx, d.Name(), c.MTU, c.Policy, c.DisableIPv6, c.KillSwitch); err != nil {
		return nil, codeFault(err, "linux_network_setup_failed", false)
	}
	if c.KillSwitch {
		report("kill_switch_active", "nftables kill switch active; protection survives process termination")
	}
	return owned, nil
}
