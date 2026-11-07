package systemvpn

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

const l7Handle = 196608

// fastTimings shortens connect's production poll interval and cleanup deadline.
func fastTimings(t *testing.T, interval, timeout time.Duration) {
	t.Helper()
	oldInterval, oldTimeout := pollInterval, cleanupTimeout
	pollInterval, cleanupTimeout = interval, timeout
	t.Cleanup(func() { pollInterval, cleanupTimeout = oldInterval, oldTimeout })
}

// chainHas reports whether any error reachable through Unwrap has message msg.
// rasError allocates per call, so the L7 startup error has no sentinel.
func chainHas(err error, msg string) bool {
	if err == nil {
		return false
	}
	if err.Error() == msg {
		return true
	}
	switch e := err.(type) {
	case interface{ Unwrap() error }:
		return chainHas(e.Unwrap(), msg)
	case interface{ Unwrap() []error }:
		for _, inner := range e.Unwrap() {
			if chainHas(inner, msg) {
				return true
			}
		}
	}
	return false
}

// l7Driver replays the L7 lab sequence: RasDial accepted, a pending status,
// a terminal 775, then HangUp not accepted. Post-HangUp status and
// enumeration behavior are supplied per test. All counters are guarded.
type l7Driver struct {
	t *testing.T

	mu                                    sync.Mutex
	preStatus, postStatus, hangups, enums int
	releases                              int
	hungUp                                bool
	afterHangup                           func(n int) (connectionState, error)
	enumerate                             func(n int) (bool, error)
	dialErr                               error
	hangupResult                          error
}

func (d *l7Driver) driver() fakeDriver {
	return fakeDriver{
		dialFn: func(Config) (uintptr, error) { return l7Handle, d.dialErr },
		statusFn: func(h uintptr) (connectionState, error) {
			d.check(h)
			d.mu.Lock()
			defer d.mu.Unlock()
			if !d.hungUp {
				d.preStatus++
				if d.preStatus == 1 {
					return connectionState{}, nil
				}
				return connectionState{code: 775}, nil
			}
			d.postStatus++
			return d.afterHangup(d.postStatus)
		},
		hangupFn: func(h uintptr) error {
			d.check(h)
			d.mu.Lock()
			defer d.mu.Unlock()
			d.hangups++
			d.hungUp = true
			if d.hangupResult != nil {
				return d.hangupResult
			}
			return errHangupNoConnection
		},
		ownedFn: func(h uintptr) (bool, error) {
			d.check(h)
			d.mu.Lock()
			defer d.mu.Unlock()
			d.enums++
			return d.enumerate(d.enums)
		},
		releaseFn: func() { d.mu.Lock(); d.releases++; d.mu.Unlock() },
	}
}

func (d *l7Driver) check(h uintptr) {
	if h != l7Handle {
		d.t.Error("touched unrelated handle", h)
	}
}

func invalidAfterHangup(int) (connectionState, error) { return connectionState{}, errInvalidHandle }
func neverInvalid(int) (connectionState, error)       { return connectionState{code: 775}, nil }
func absent(int) (bool, error)                        { return false, nil }

func runL7(t *testing.T, d *l7Driver) ([]string, error) {
	t.Helper()
	var states []string
	s, err := connectObserved(context.Background(), testConfig(), d.driver(), func(state string) { states = append(states, state) })
	if s != nil {
		t.Fatal("failed startup returned a session")
	}
	return states, err
}

// Acceptance 1.
func TestL7HangupNotAcceptedReleasesAfterCorroboratedInvalidation(t *testing.T) {
	fastTimings(t, time.Millisecond, time.Second)
	d := &l7Driver{t: t, afterHangup: invalidAfterHangup, enumerate: absent}
	states, err := runL7(t, d)
	if err == nil || err.Error() != "ikev2_native_operation_failed" {
		t.Fatal("startup error not returned", err)
	}
	var joined *startupCleanupError
	if errors.As(err, &joined) {
		t.Fatal("successful cleanup wrapped the startup error", err)
	}
	if d.hangups != 1 || d.releases != 1 || d.postStatus != 1 || d.enums != 1 {
		t.Fatal("hangups", d.hangups, "releases", d.releases, "status", d.postStatus, "enums", d.enums)
	}
	if !reflect.DeepEqual(states, []string{"pending", "succeeded"}) {
		t.Fatal(states)
	}
}

// Acceptance 2.
func TestL7WithoutLaterInvalidationTimesOutAndKeepsStartupError(t *testing.T) {
	fastTimings(t, time.Millisecond, 20*time.Millisecond)
	d := &l7Driver{t: t, afterHangup: neverInvalid, enumerate: func(int) (bool, error) {
		t.Error("enumerated without a fresh invalid status")
		return false, nil
	}}
	states, err := runL7(t, d)
	if err == nil || err.Error() != "ikev2_cleanup_timeout" {
		t.Fatal(err)
	}
	if !chainHas(err, "ikev2_native_operation_failed") {
		t.Fatal("startup error unreachable", err)
	}
	if d.releases != 0 || d.hangups != 1 {
		t.Fatal("releases", d.releases, "hangups", d.hangups)
	}
	if !reflect.DeepEqual(states, []string{"pending", "failed"}) {
		t.Fatal(states)
	}
}

// Decision 6: Error() is the cleanup string; errors.Is reaches both causes.
func TestStartupAndCleanupFailureBothReachable(t *testing.T) {
	fastTimings(t, time.Millisecond, 20*time.Millisecond)
	dialErr := errors.New("dial failed")
	d := &l7Driver{t: t, dialErr: dialErr, afterHangup: neverInvalid, enumerate: absent}
	_, err := runL7(t, d)
	if err.Error() != "ikev2_cleanup_timeout" || !errors.Is(err, dialErr) {
		t.Fatal(err)
	}
	var joined *startupCleanupError
	if !errors.As(err, &joined) || !errors.Is(err, joined.cleanup) {
		t.Fatal("cleanup error unreachable", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	d = &l7Driver{t: t, afterHangup: invalidAfterHangup, enumerate: func(int) (bool, error) { return false, errors.New("enum") }}
	f := d.driver()
	dial := f.dialFn
	f.dialFn = func(c Config) (uintptr, error) { cancel(); return dial(c) }
	_, err = connect(ctx, testConfig(), f)
	if err == nil || err.Error() != "ikev2_cleanup_failed" || !errors.Is(err, context.Canceled) || err == context.Canceled {
		t.Fatal(err)
	}
}

// Acceptance 3.
func TestEnumerationListingHandleDelaysRelease(t *testing.T) {
	t.Run("disappears", func(t *testing.T) {
		fastTimings(t, time.Millisecond, time.Second)
		d := &l7Driver{t: t, afterHangup: invalidAfterHangup, enumerate: func(n int) (bool, error) { return n < 4, nil }}
		states, err := runL7(t, d)
		if err == nil || err.Error() != "ikev2_native_operation_failed" {
			t.Fatal(err)
		}
		if d.releases != 1 || d.enums != 4 || d.postStatus != 4 {
			t.Fatal("releases", d.releases, "enums", d.enums, "status", d.postStatus)
		}
		if !reflect.DeepEqual(states, []string{"pending", "succeeded"}) {
			t.Fatal(states)
		}
	})
	t.Run("stays", func(t *testing.T) {
		fastTimings(t, time.Millisecond, 20*time.Millisecond)
		d := &l7Driver{t: t, afterHangup: invalidAfterHangup, enumerate: func(int) (bool, error) { return true, nil }}
		_, err := runL7(t, d)
		if err == nil || err.Error() != "ikev2_cleanup_timeout" || d.releases != 0 || d.enums < 2 || d.enums != d.postStatus {
			t.Fatal(err, d.releases, d.enums, d.postStatus)
		}
	})
}

// Acceptance 4.
func TestEnumerationErrorFailsCleanupWithoutRelease(t *testing.T) {
	fastTimings(t, time.Millisecond, time.Second)
	d := &l7Driver{t: t, afterHangup: invalidAfterHangup, enumerate: func(int) (bool, error) { return false, errors.New("enum") }}
	states, err := runL7(t, d)
	if err == nil || err.Error() != "ikev2_cleanup_failed" || d.releases != 0 || d.enums != 1 {
		t.Fatal(err, d.releases, d.enums)
	}
	if !chainHas(err, "ikev2_native_operation_failed") {
		t.Fatal("startup error unreachable", err)
	}
	if !reflect.DeepEqual(states, []string{"pending", "failed"}) {
		t.Fatal(states)
	}
}

// Acceptance 5.
func TestNoEarlyReleaseBeforeHangupOrWhilePending(t *testing.T) {
	t.Run("status 6 before HangUp", func(t *testing.T) {
		fastTimings(t, time.Millisecond, 20*time.Millisecond)
		hungUp, releases, enums := false, 0, 0
		d := fakeDriver{
			dialFn: func(Config) (uintptr, error) { return l7Handle, nil },
			statusFn: func(uintptr) (connectionState, error) {
				if !hungUp {
					return connectionState{}, errInvalidHandle
				}
				return connectionState{code: 775}, nil
			},
			hangupFn:  func(uintptr) error { hungUp = true; return errHangupNoConnection },
			ownedFn:   func(uintptr) (bool, error) { enums++; return false, nil },
			releaseFn: func() { releases++ },
		}
		_, err := connect(context.Background(), testConfig(), d)
		if err == nil || err.Error() != "ikev2_cleanup_timeout" || !errors.Is(err, errInvalidHandle) || releases != 0 || enums != 0 {
			t.Fatal(err, releases, enums)
		}
	})
	t.Run("pending HangUp", func(t *testing.T) {
		statuses := 0
		d := fakeDriver{
			hangupFn:  func(uintptr) error { return errDialPending },
			statusFn:  func(uintptr) (connectionState, error) { statuses++; return connectionState{}, errInvalidHandle },
			ownedFn:   func(uintptr) (bool, error) { t.Error("enumerated while pending"); return false, nil },
			releaseFn: func() { t.Error("released while dial pending") },
		}
		s := &Session{driver: d, handle: l7Handle, interval: time.Millisecond, cleanupTimeout: 10 * time.Millisecond}
		if err := s.Close(); err == nil || err.Error() != "ikev2_cleanup_timeout" || statuses != 0 {
			t.Fatal(err, statuses)
		}
	})
	t.Run("pending then not accepted", func(t *testing.T) {
		hangups, releases := 0, 0
		d := fakeDriver{
			hangupFn: func(uintptr) error {
				hangups++
				if hangups < 3 {
					return errDialPending
				}
				return errHangupNoConnection
			},
			statusFn:  func(uintptr) (connectionState, error) { return connectionState{}, errInvalidHandle },
			releaseFn: func() { releases++ },
		}
		s := &Session{driver: d, handle: l7Handle, interval: time.Millisecond, cleanupTimeout: time.Second}
		if err := s.Close(); err != nil || hangups != 3 || releases != 1 {
			t.Fatal(err, hangups, releases)
		}
	})
}

// Acceptance 8.
func TestAcceptedHangupReleasesWithoutEnumeration(t *testing.T) {
	releases := 0
	d := fakeDriver{
		hangupFn:  func(uintptr) error { return nil },
		statusFn:  func(uintptr) (connectionState, error) { return connectionState{}, errInvalidHandle },
		ownedFn:   func(uintptr) (bool, error) { t.Error("accepted path enumerated"); return true, nil },
		releaseFn: func() { releases++ },
	}
	s := &Session{driver: d, handle: l7Handle, interval: time.Millisecond, cleanupTimeout: time.Second}
	if err := s.Close(); err != nil || releases != 1 {
		t.Fatal(err, releases)
	}
}

// A legacy driver returning errInvalidHandle from HangUp takes the stricter
// not-accepted path rather than being treated as acknowledged.
func TestHangupInvalidHandleRequiresCorroboration(t *testing.T) {
	d := fakeDriver{
		hangupFn:  func(uintptr) error { return errInvalidHandle },
		statusFn:  func(uintptr) (connectionState, error) { return connectionState{}, errInvalidHandle },
		ownedFn:   func(uintptr) (bool, error) { return true, nil },
		releaseFn: func() { t.Error("released without corroboration") },
	}
	s := &Session{driver: d, handle: l7Handle, interval: time.Millisecond, cleanupTimeout: 10 * time.Millisecond}
	if err := s.Close(); err == nil || err.Error() != "ikev2_cleanup_timeout" {
		t.Fatal(err)
	}
}

// Acceptance 9.
func TestConcurrentCloseOnNotAcceptedPath(t *testing.T) {
	d := &l7Driver{t: t, afterHangup: invalidAfterHangup, enumerate: func(n int) (bool, error) { return n < 3, nil }}
	s := &Session{driver: d.driver(), handle: l7Handle, interval: time.Millisecond, cleanupTimeout: time.Second}
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.Close()
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.hangups != 1 || d.releases != 1 || d.enums != 3 {
		t.Fatal("hangups", d.hangups, "releases", d.releases, "enums", d.enums)
	}

	failing := &l7Driver{t: t, afterHangup: invalidAfterHangup, enumerate: func(int) (bool, error) { return false, errors.New("enum") }}
	s = &Session{driver: failing.driver(), handle: l7Handle, interval: time.Millisecond, cleanupTimeout: time.Second}
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.Close()
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != errs[0] || err == nil || err.Error() != "ikev2_cleanup_failed" {
			t.Fatal(errs)
		}
	}
	failing.mu.Lock()
	defer failing.mu.Unlock()
	if failing.hangups != 1 || failing.releases != 0 {
		t.Fatal(failing.hangups, failing.releases)
	}
}
