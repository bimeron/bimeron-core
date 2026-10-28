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
		err := s.native.Close()
		s.mu.Lock()
		lost := s.lost
		s.mu.Unlock()
		if err != nil || lost {
			_ = s.guard.Retain()
			s.closeErr = fault("ikev2_protection_retained_run_recover", false)
			return
		}
		if s.cleanupDNS() != nil {
			_ = s.guard.Retain()
			s.closeErr = fault("ikev2_dns_cleanup_failed_run_recover", false)
			return
		}
		if s.guard.Close() != nil {
			s.closeErr = fault("ikev2_protection_cleanup_failed_run_recover", false)
		}
	})
	return s.closeErr
}
