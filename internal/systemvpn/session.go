package systemvpn

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	stateConnected    = 0x2000
	stateDisconnected = 0x2001
)

type connectionState struct{ state, code uint32 }

// driver separates native calls from lifecycle tests. A nonzero handle belongs
// to the caller even when dial fails, as required by RasDial.
type driver interface {
	inspect(Config) error
	dial(Config) (uintptr, error)
	status(uintptr) (connectionState, error)
	hangup(uintptr) error
	release()
}

type Session struct {
	driver          driver
	handle          uintptr
	interval        time.Duration
	cleanupTimeout  time.Duration
	once            sync.Once
	closeErr        error
	cleanupObserver func(string)
}

func connect(ctx context.Context, cfg Config, d driver) (*Session, error) {
	return connectObserved(ctx, cfg, d, nil)
}

func connectObserved(ctx context.Context, cfg Config, d driver, observe func(string)) (*Session, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := d.inspect(cfg); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h, err := d.dial(cfg)
	s := &Session{driver: d, handle: h, interval: 100 * time.Millisecond, cleanupTimeout: 30 * time.Second, cleanupObserver: observe}
	if err == nil && h == 0 {
		err = errors.New("ikev2_invalid_connection_handle")
	}
	if err == nil {
		err = s.wait(ctx, true)
	}
	if err != nil {
		if cleanupErr := s.Close(); cleanupErr != nil {
			return nil, cleanupErr
		}
		return nil, err
	}
	return s, nil
}

func (s *Session) Wait(ctx context.Context) error { return s.wait(ctx, false) }

func (s *Session) wait(ctx context.Context, connecting bool) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		status, err := s.driver.status(s.handle)
		if err != nil {
			return err
		}
		if status.code != 0 {
			return rasError(status.code)
		}
		if status.state == stateDisconnected {
			return errors.New("ikev2_disconnected")
		}
		if connecting && status.state == stateConnected {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Close waits for handle invalidation, not merely RasHangUp's acknowledgement.
// It deliberately ignores the connection context so cancellation cannot skip
// rollback. Only the handle returned by our own dial call is ever disconnected.
func (s *Session) Close() error {
	s.once.Do(func() {
		if s.cleanupObserver != nil {
			s.cleanupObserver("pending")
			defer func() {
				if s.closeErr != nil {
					s.cleanupObserver("failed")
				} else {
					s.cleanupObserver("succeeded")
				}
			}()
		}
		if s.handle == 0 {
			s.driver.release()
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.cleanupTimeout)
		defer cancel()
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			err := s.driver.hangup(s.handle)
			if err == nil || errors.Is(err, errInvalidHandle) {
				break
			}
			if !errors.Is(err, errDialPending) {
				s.closeErr = errors.New("ikev2_cleanup_failed")
				return
			}
			select {
			case <-ctx.Done():
				s.closeErr = errors.New("ikev2_cleanup_timeout")
				return
			case <-ticker.C:
			}
		}
		for {
			_, err := s.driver.status(s.handle)
			if errors.Is(err, errInvalidHandle) {
				s.driver.release()
				return
			}
			if err != nil {
				s.closeErr = errors.New("ikev2_cleanup_failed")
				return
			}
			select {
			case <-ctx.Done():
				s.closeErr = errors.New("ikev2_cleanup_timeout")
				return
			case <-ticker.C:
			}
		}
	})
	return s.closeErr
}

var errInvalidHandle = errors.New("ikev2_connection_handle_invalid")
var errDialPending = errors.New("ikev2_dial_pending")

// Return only bounded codes, never native error strings containing identities.
func rasError(code uint32) error {
	switch code {
	case 6:
		return errInvalidHandle
	case 691:
		return errors.New("ikev2_authentication_failed")
	case 798, 13801, 13806:
		return errors.New("ikev2_certificate_or_authentication_failed")
	case 623:
		return errors.New("ikev2_windows_profile_not_found")
	case 5:
		return errors.New("ikev2_access_denied")
	case 809:
		return errors.New("ikev2_server_unreachable")
	default:
		return errors.New("ikev2_native_operation_failed")
	}
}
