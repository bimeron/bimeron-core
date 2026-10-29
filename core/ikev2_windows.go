//go:build windows

package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"bimeron/internal/killswitch"
	"bimeron/internal/systemvpn"
	"bimeron/internal/windowsnet"
)

type ikev2Backend struct{}

func newIKEv2Backend() backend { return ikev2Backend{} }
func (ikev2Backend) Acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !windowsnet.Elevated() {
		return nil, fault("administrator_required", false)
	}
	release, err := windowsnet.Acquire()
	if err != nil {
		return nil, fault("session_lock_failed", false)
	}
	pending, err := killswitch.Pending()
	if err != nil || pending {
		release()
		return nil, fault("ikev2_existing_kill_switch_requires_recovery", false)
	}
	return release, nil
}
func (ikev2Backend) Open(ctx context.Context, c SessionConfig, report func(string, string)) (session, error) {
	setup, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	tag := ""
	if c.IKEv2.KillSwitch {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, fault("session_identity_failed", false)
		}
		tag = "BimeronIKEv2DNS:" + hex.EncodeToString(id[:])
		if err := windowsnet.CheckIKEv2DNS(setup); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fault("ikev2_conflicting_dns_policy_run_recover", false)
		}
	}
	report("ikev2_connect", "Connecting through the Windows IKEv2 client")
	s, err := systemvpn.OpenObserved(setup, *c.IKEv2, func(state string) { c.updateNative(func(n *NativeStatus) { n.RASCleanup = state }) })
	if err != nil {
		c.updateNative(func(n *NativeStatus) {
			switch err.Error() {
			case "ikev2_windows_profile_not_found":
				n.ProfileReadiness = "missing"
			case "ikev2_saved_credentials_required", "ikev2_saved_eap_identity_required":
				n.CredentialReadiness = "missing"
			case "ikev2_certificate_or_authentication_failed":
				n.CertificateReadiness = "authentication_failed"
			case "ikev2_cleanup_failed", "ikev2_cleanup_timeout":
				n.RASCleanup = "failed"
			}
		})
		if err == context.Canceled {
			return nil, err
		}
		if err == context.DeadlineExceeded {
			return nil, fault("ikev2_connect_timeout", false)
		}
		return nil, fault(err.Error(), false)
	}
	c.updateNative(func(n *NativeStatus) {
		n.ProfileReadiness = "validated"
		n.CredentialReadiness = "usable"
		n.CertificateReadiness = "windows_authenticated"
	})
	observed := &observedNativeSession{native: s, config: c}
	if !c.IKEv2.KillSwitch {
		return observed, nil
	}
	// RAS bootstrap is deliberately outside the protection boundary. Connected
	// is not published until WFP and the DNS policy have both been installed.
	endpoint, err := s.ProtectionEndpoint()
	if err != nil {
		if observed.Close() != nil {
			return nil, fault("ikev2_cleanup_failed", false)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fault(err.Error(), false)
	}
	network, err := windowsnet.ObserveVPN(setup, c.IKEv2.WindowsProfile)
	if err != nil {
		if observed.Close() != nil {
			return nil, fault("ikev2_cleanup_failed", false)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fault("ikev2_protection_network_failed", false)
	}
	guard, err := killswitch.ArmIKEv2(network.Index, network.LUID, endpoint)
	if err != nil {
		if observed.Close() != nil {
			return nil, fault("ikev2_cleanup_failed", false)
		}
		return nil, fault("ikev2_protection_install_failed", false)
	}
	c.updateNative(func(n *NativeStatus) { n.WFP = "active"; n.DNS = "installing" })
	protected := &protectedIKEv2Session{native: observed, guard: guard, update: c.nativeUpdate, cleanupDNS: func() error {
		cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		return windowsnet.CleanupIKEv2DNS(cleanup, tag, network.DNS)
	}}
	if err == nil {
		// Do not terminate a mutating CIM call halfway through caller cancellation:
		// wait for its bounded completion, then roll back under the traffic guard.
		report("ikev2_dns_protection", "Configuring protected tunnel DNS")
		dnsSetup, finish := context.WithTimeout(context.Background(), 45*time.Second)
		err = windowsnet.ConfigureIKEv2DNS(dnsSetup, tag, network.DNS)
		if dnsSetup.Err() != nil {
			protected.lost = true
			c.updateNative(func(n *NativeStatus) { n.DNS = "unknown" })
		} // Outcome uncertain; explicit recovery.
		finish()
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		if cleanupErr := protected.Close(); cleanupErr != nil {
			return nil, cleanupErr
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fault("ikev2_dns_protection_install_failed", false)
	}
	c.updateNative(func(n *NativeStatus) { n.DNS = "active" })
	report("ikev2_protection_active", "Persistent Windows traffic protection and tunnel DNS are active")
	return protected, nil
}
