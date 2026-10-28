//go:build windows

package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bimeron/internal/killswitch"
	"bimeron/internal/windowsnet"
	stack "github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	winTun "golang.zx2c4.com/wireguard/tun"
)

type windowsPlatform struct{ killSwitch bool }

func init() { winTun.WintunTunnelType = "Bimeron" }

func newPlatform(c SessionConfig) platform { return windowsPlatform{killSwitch: c.KillSwitch} }
func (p windowsPlatform) Acquire(ctx context.Context) (func(), error) {
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
	}
	return release, nil
}
func (windowsPlatform) Inspect(ctx context.Context, name string, startup bool) (networkPath, error) {
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
func (windowsPlatform) Open(ctx context.Context, c SessionConfig, h *flowRouter, report func(string, string)) (result link, err error) {
	owned := &cleanup{}
	defer func() {
		if err != nil {
			if cleanupErr := owned.Close(); cleanupErr != nil {
				err = cleanupErr
			}
		}
	}()
	report("adapter_create", "Creating Wintun adapter")
	d, err := tun.Open(c.Name, uint32(c.MTU))
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
	iface, err := net.InterfaceByName(d.Name())
	if err != nil {
		return nil, fault("adapter_lookup_failed", false)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fault("session_id_failed", false)
	}
	nc := windowsnet.Config{Name: d.Name(), Tag: "BimeronCore:" + hex.EncodeToString(random[:]), Index: iface.Index, MTU: c.MTU}
	var guard *killswitch.Guard
	networkCleaned := false
	if c.KillSwitch {
		owned.add(func() error {
			if guard == nil || !networkCleaned {
				return nil
			}
			return guard.Close()
		})
	}
	// Register rollback BEFORE setup. It uses an independent timeout after Ctrl+C.
	owned.add(func() error {
		if err := windowsnet.Cleanup(nc); err != nil {
			return err
		}
		networkCleaned = true
		return nil
	})
	report("network_setup", "Configuring routes and tunnel DNS")
	setupCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	timing, err := windowsnet.Configure(setupCtx, nc)
	if err != nil {
		if ctx.Err() != nil {
			return nil, context.Canceled
		}
		return nil, fault("network_setup_failed", false)
	}
	report("network_setup_timing", fmt.Sprintf("Windows setup: interface %d ms, addresses %d ms, DNS %d ms, routes %d ms, NRPT %d ms, cache %d ms", timing.InterfaceMs, timing.AddressesMs, timing.DNSMs, timing.RoutesMs, timing.NRPTMs, timing.CacheMs))
	if c.KillSwitch {
		report("kill_switch_arm", "Installing persistent Windows protection")
		guard, err = killswitch.Arm(iface.Index, c.Policy, c.DisableIPv6)
		if err != nil {
			return nil, fault("kill_switch_arm_failed_run_recover", false)
		}
		report("kill_switch_active", "Kill switch active; protection survives process termination")
	}
	return owned, nil
}
