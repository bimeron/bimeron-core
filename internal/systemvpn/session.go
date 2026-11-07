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

// Production timings. Tests shorten them to exercise deadlines quickly.
var (
	pollInterval   = 100 * time.Millisecond
	cleanupTimeout = 30 * time.Second
)

type connectionState struct{ state, code uint32 }

// driver separates native calls from lifecycle tests. A nonzero handle belongs
// to the caller even when dial fails, as required by RasDial.
type driver interface {
	inspect(Config) error
	dial(Config) (uintptr, error)
	status(uintptr) (connectionState, error)
	hangup(uintptr) error
	// owned reports whether the exact owned handle is still listed by a
	// read-only, bounded connection enumeration. It never adopts, disconnects
	// or inspects unrelated connections.
	owned(uintptr) (bool, error)
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
	s := &Session{driver: d, handle: h, interval: pollInterval, cleanupTimeout: cleanupTimeout, cleanupObserver: observe}
	if err == nil && h == 0 {
		err = errors.New("ikev2_invalid_connection_handle")
	}
	if err == nil {
		err = s.wait(ctx, true)
	}
	if err != nil {
		if cleanupErr := s.Close(); cleanupErr != nil {
			return nil, &startupCleanupError{cleanup: cleanupErr, startup: err}
		}
		return nil, err
	}
	return s, nil
}

// startupCleanupError reports a failed rollback of a failed startup. Error()
// is exactly the cleanup error so callers matching public strings are
// unaffected, while errors.Is still reaches the startup cause.
type startupCleanupError struct{ cleanup, startup error }

func (e *startupCleanupError) Error() string   { return e.cleanup.Error() }
func (e *startupCleanupError) Unwrap() []error { return []error{e.cleanup, e.startup} }

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
		accepted := true
		for {
			err := s.driver.hangup(s.handle)
			if err == nil {
				break
			}
			// HangUp gave no acknowledgement. The hangup classifier never returns
			// errInvalidHandle; should a driver still do so, it is handled as the
			// stricter not-accepted path, which requires corroboration before
			// release, rather than as an acknowledged hangup.
			if errors.Is(err, errHangupNoConnection) || errors.Is(err, errInvalidHandle) {
				accepted = false
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
		// Only status observed after HangUp counts. Without a HangUp
		// acknowledgement, the owned handle must also be absent from a fresh
		// enumeration in the same probe iteration.
		for {
			_, err := s.driver.status(s.handle)
			if errors.Is(err, errInvalidHandle) {
				if accepted {
					s.driver.release()
					return
				}
				present, enumErr := s.driver.owned(s.handle)
				if enumErr != nil {
					s.closeErr = errors.New("ikev2_cleanup_failed")
					return
				}
				if !present {
					s.driver.release()
					return
				}
			} else if err != nil {
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

// errHangupNoConnection means RasHangUp returned 6 or 668 after terminal dial
// evidence. It is not an acknowledgement and never implies an invalid handle.
var errHangupNoConnection = errors.New("ikev2_hangup_no_connection")

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
