package core

import (
	"context"
	"sync"
)

type retainedGuard interface {
	Close() error
	Retain() error
}

// Native protection is released only after an explicitly requested stop and
// successful RAS/DNS cleanup. Unexpected loss keeps the persistent policy armed.
type protectedIKEv2Session struct {
	native     session
	guard      retainedGuard
	cleanupDNS func() error
	mu         sync.Mutex
	lost       bool
	once       sync.Once
	closeErr   error
	update     func(func(*NativeStatus))
}

func (s *protectedIKEv2Session) Wait(ctx context.Context) error {
	err := s.native.Wait(ctx)
	if ctx.Err() == nil {
		s.mu.Lock()
		s.lost = true
		s.mu.Unlock()
	}
	return err
}
func (s *protectedIKEv2Session) Close() error {
	s.once.Do(func() {
		update := func(f func(*NativeStatus)) {
			if s.update != nil {
				s.update(f)
			}
		}
		update(func(n *NativeStatus) { n.RASCleanup = "pending" })
		err := s.native.Close()
		update(func(n *NativeStatus) {
			if err != nil {
				n.RASCleanup = "failed"
			} else {
				n.RASCleanup = "succeeded"
			}
		})
		s.mu.Lock()
		lost := s.lost
		s.mu.Unlock()
		if err != nil || lost {
			_ = s.guard.Retain()
			update(func(n *NativeStatus) {
				n.WFP = "retained"
				if n.DNS == "active" {
					n.DNS = "retained"
				}
				n.RecoveryRequired = true
			})
			s.closeErr = fault("ikev2_protection_retained_run_recover", false)
			return
		}
		update(func(n *NativeStatus) { n.DNSCleanup = "pending" })
		if dnsErr := s.cleanupDNS(); dnsErr != nil {
			_ = s.guard.Retain()
			update(func(n *NativeStatus) {
				n.DNS = "unknown"
				if dnsErr.Error() == "ikev2_owned_dns_policy_modified" {
					n.DNS = "modified"
				}
				n.DNSCleanup = "failed"
				n.WFP = "retained"
				n.RecoveryRequired = true
			})
			s.closeErr = fault("ikev2_dns_cleanup_failed_run_recover", false)
			return
		}
		update(func(n *NativeStatus) { n.DNS = "inactive"; n.DNSCleanup = "succeeded"; n.WFPCleanup = "pending" })
		if s.guard.Close() != nil {
			update(func(n *NativeStatus) { n.WFP = "unknown"; n.WFPCleanup = "failed"; n.RecoveryRequired = true })
			s.closeErr = fault("ikev2_protection_cleanup_failed_run_recover", false)
		} else {
			update(func(n *NativeStatus) { n.WFP = "inactive"; n.WFPCleanup = "succeeded" })
		}
	})
	return s.closeErr
}
