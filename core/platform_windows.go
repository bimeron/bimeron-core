//go:build windows

package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bimeron/internal/killswitch"
	"bimeron/internal/routing"
	"bimeron/internal/windowsnet"
	stack "github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"golang.org/x/sys/windows"
	winTun "golang.zx2c4.com/wireguard/tun"
)

// windowsPlatform owns the kill switch for a whole run. Acquire installs it
// before any session traffic, each Open re-arms it for the new adapter, and the
// release returned by Acquire removes it unless RetainProtection was called.
type windowsPlatform struct {
	killSwitch  bool
	policy      *routing.Policy
	disableIPv6 bool
	guard       *killswitch.Guard
	retain      bool
	releaseErr  error // a failed removal, read after release returns
}

var _ protectedPlatform = (*windowsPlatform)(nil)

func init() { winTun.WintunTunnelType = windowsnet.TunnelType }

func newPlatform(c SessionConfig) platform {
	return &windowsPlatform{killSwitch: c.KillSwitch, policy: c.Policy, disableIPv6: c.DisableIPv6}
}
func (p *windowsPlatform) Protected() bool     { return p.guard != nil }
func (p *windowsPlatform) RetainProtection()   { p.retain = true }
func (p *windowsPlatform) ReleaseError() error { return p.releaseErr }
func (p *windowsPlatform) Acquire(ctx context.Context) (func(), error) {
	if !windowsnet.Elevated() {
		return nil, fault("administrator_required", false)
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fault("executable_path_failed", false)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(exe), "wintun.dll")); err != nil {
		return nil, fault("wintun_dll_missing", false)
	}
	release, err := windowsnet.Acquire()
	if err != nil {
		return nil, fault("session_lock_failed", false)
	}
	// Never implicitly remove protection retained after a crashed session.
	if pending, inspectErr := killswitch.NativePending(); inspectErr != nil || pending {
		release()
		return nil, fault("ikev2_protection_pending_run_recover", false)
	}
	if !p.killSwitch {
		pending, err := killswitch.Pending()
		if err != nil {
			release()
			return nil, fault("kill_switch_inspect_failed", false)
		}
		if pending {
			release()
			return nil, fault("kill_switch_pending_run_recover", false)
		}
	} else {
		// Protect the run before Inspect, key resolution, DNS or transport
		// traffic. Without an adapter yet, only the tunnel permit is missing;
		// the arm replaces protection retained by an earlier process in place.
		guard, err := killswitch.Arm(0, p.policy, p.disableIPv6)
		if err != nil {
			release()
			return nil, fault("kill_switch_arm_failed_run_recover", false)
		}
		p.guard, p.retain, p.releaseErr = guard, false, nil
	}
	return func() {
		if p.guard != nil {
			if p.retain {
				_ = p.guard.Detach()
			} else {
				// A failed removal leaves the persistent filters installed:
				// the system stays fail-closed until Recover.
				p.releaseErr = p.guard.Close()
			}
		}
		release()
	}, nil
}
func (*windowsPlatform) Inspect(ctx context.Context, name string, startup bool) (networkPath, error) {
	s, err := windowsnet.Observe(ctx, name, startup)
	if err != nil {
		if strings.Contains(err.Error(), "DNS recovery failed") {
			return networkPath{}, fault("dns_recovery_failed", false)
		}
		if strings.Contains(err.Error(), "Tunnel adapter disappeared") {
			return networkPath{}, fault("tunnel_adapter_lost", false)
		}
		if strings.Contains(err.Error(), "Tunnel name is already in use") {
			return networkPath{}, fault("adapter_name_in_use", false)
		}
		if strings.Contains(err.Error(), "Existing NRPT rules") {
			return networkPath{}, fault("conflicting_dns_policy", false)
		}
		return networkPath{}, fault("network_inspect_failed", true)
	}
	identity, _ := json.Marshal(s)
	return networkPath{identity: string(identity), dns: s.DNS, dialer: net.Dialer{Timeout: 15 * time.Second, Control: windowsnet.BoundDialer(s)}}, nil
}
func (p *windowsPlatform) Open(ctx context.Context, c SessionConfig, h *flowRouter, report func(string, string)) (result link, err error) {
	owned := &cleanup{}
	defer func() {
		if err != nil {
			if cleanupErr := owned.Close(); cleanupErr != nil {
				err = cleanupErr
			}
		}
	}()
	report("adapter_create", "Creating Wintun adapter")
	// A stale interface left by an unclean exit is recreated under its GUID,
	// which keeps the name; a foreign interface still conflicts.
	stale, err := windowsnet.ReclaimStaleTunnel(c.Name)
	if err != nil {
		return nil, fault("adapter_name_in_use", false)
	}
	// A new adapter also gets a known GUID: the tunnel is identified by it,
	// never by name, so an interface that takes the name meanwhile is never
	// configured as the tunnel.
	guid := stale
	if guid == nil {
		fresh, err := windows.GenerateGUID()
		if err != nil {
			return nil, fault("adapter_create_failed", false)
		}
		guid = &fresh
	}
	winTun.WintunStaticRequestedGUID = guid
	d, err := tun.Open(c.Name, uint32(c.MTU))
	winTun.WintunStaticRequestedGUID = nil
	if err != nil {
		return nil, fault("adapter_create_failed", false)
	}
	owned.add(func() error { d.Close(); return nil })
	s, err := stack.CreateStack(&stack.Config{LinkEndpoint: d, TransportHandler: h})
	if err != nil {
		return nil, fault("packet_stack_failed", false)
	}
	owned.add(func() error { s.Close(); return nil })
	owned.add(func() error { h.Close(); return nil })
	index, err := windowsnet.TunnelInterface(*guid, c.Name)
	if errors.Is(err, windowsnet.ErrTunnelNameTaken) {
		return nil, fault("adapter_name_in_use", false)
	}
	if err != nil {
		return nil, fault("adapter_lookup_failed", false)
	}
	// Re-arm before network setup so the tunnel is permitted the moment it
	// is configured. Neither rollback nor Close removes run protection.
	if p.guard != nil {
		report("kill_switch_arm", "Installing persistent Windows protection")
		armed, armErr := killswitch.Arm(index, p.policy, p.disableIPv6)
		if armErr != nil {
			// The failed attempt removed only itself; the previous set remains.
			return nil, fault("kill_switch_arm_failed_run_recover", false)
		}
		// The new set replaced the previous rules; only its session is left.
		_ = p.guard.Detach()
		p.guard = armed
		report("kill_switch_active", "Kill switch active; protection survives process termination")
		// Closing the adapter withdraws its permit, so a later interface that
		// reuses the LUID is never permitted; the rest of the set stays.
		owned.add(func() error {
			if p.guard == nil {
				return nil
			}
			early, err := killswitch.Arm(0, p.policy, p.disableIPv6)
			if err != nil {
				return err
			}
			_ = p.guard.Detach()
			p.guard = early
			return nil
		})
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fault("session_id_failed", false)
	}
	nc := windowsnet.Config{Name: c.Name, Tag: "BimeronCore:" + hex.EncodeToString(random[:]), Index: index, GUID: *guid, MTU: c.MTU}
	// Register rollback BEFORE setup. It uses an independent timeout after Ctrl+C.
	owned.add(func() error { return windowsnet.Cleanup(nc) })
	report("network_setup", "Configuring routes and tunnel DNS")
	setupCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	timing, err := windowsnet.Configure(setupCtx, nc)
	if err != nil {
		if ctx.Err() != nil {
			return nil, context.Canceled
		}
		if strings.Contains(err.Error(), "effective NRPT policy") {
			// The session rule was installed but Windows does not apply it,
			// for example because another source of NRPT policy took over.
			return nil, fault("conflicting_dns_policy", false)
		}
		return nil, fault("network_setup_failed", false)
	}
	report("network_setup_timing", fmt.Sprintf("Windows setup: interface %d ms, addresses %d ms, DNS %d ms, routes %d ms, NRPT %d ms, cache %d ms", timing.InterfaceMs, timing.AddressesMs, timing.DNSMs, timing.RoutesMs, timing.NRPTMs, timing.CacheMs))
	return owned, nil
}
