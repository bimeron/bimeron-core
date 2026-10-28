package systemvpn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeDriver struct {
	inspectFn func(Config) error
	dialFn    func(Config) (uintptr, error)
	statusFn  func(uintptr) (connectionState, error)
	hangupFn  func(uintptr) error
}

func (d fakeDriver) inspect(c Config) error {
	if d.inspectFn != nil {
		return d.inspectFn(c)
	}
	return nil
}
func (d fakeDriver) dial(c Config) (uintptr, error)            { return d.dialFn(c) }
func (d fakeDriver) status(h uintptr) (connectionState, error) { return d.statusFn(h) }
func (d fakeDriver) hangup(h uintptr) error                    { return d.hangupFn(h) }

func testConfig() Config {
	return Config{WindowsProfile: "Corporate VPN", ServerName: "vpn.example.com"}
}

func TestRollbackOwnsHandleEvenOnDialFailure(t *testing.T) {
	for _, dialErr := range []error{errors.New("dial failed"), nil} {
		t.Run("dial_error="+stringBool(dialErr != nil), func(t *testing.T) {
			closed := false
			d := fakeDriver{
				dialFn: func(Config) (uintptr, error) { return 42, dialErr },
				statusFn: func(h uintptr) (connectionState, error) {
					if h != 42 {
						t.Fatal("touched unrelated handle")
					}
					if closed {
						return connectionState{}, errInvalidHandle
					}
					return connectionState{code: 691}, nil
				},
				hangupFn: func(h uintptr) error {
					if h != 42 {
						t.Fatal(h)
					}
					closed = true
					return nil
				},
			}
			if s, err := connect(context.Background(), testConfig(), d); err == nil || s != nil || !closed {
				t.Fatal("failed dial was not rolled back", s, err)
			}
		})
	}
}
func stringBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func TestCancelDialStillWaitsForCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	closed := false
	d := fakeDriver{
		dialFn: func(Config) (uintptr, error) { cancel(); return 7, nil },
		statusFn: func(uintptr) (connectionState, error) {
			if closed {
				return connectionState{}, errInvalidHandle
			}
			t.Fatal("cancelled dial polled before rollback")
			return connectionState{}, nil
		},
		hangupFn: func(uintptr) error { closed = true; return nil },
	}
	if _, err := connect(ctx, testConfig(), d); !errors.Is(err, context.Canceled) || !closed {
		t.Fatal(err, closed)
	}
}

func TestDialAcknowledgementIsNotConnected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	closed := false
	d := fakeDriver{
		dialFn: func(Config) (uintptr, error) { return 7, nil },
		statusFn: func(uintptr) (connectionState, error) {
			if closed {
				return connectionState{}, errInvalidHandle
			}
			return connectionState{}, nil
		},
		hangupFn: func(uintptr) error { closed = true; return nil },
	}
	if s, err := connect(ctx, testConfig(), d); !errors.Is(err, context.DeadlineExceeded) || s != nil || !closed {
		t.Fatal("dial acknowledgement reported as connected", s, err)
	}
}

func TestInspectionFailureNeverDialsOrDisconnects(t *testing.T) {
	d := fakeDriver{inspectFn: func(Config) error { return errors.New("unsafe profile") }, dialFn: func(Config) (uintptr, error) { t.Fatal("dial after failed inspection"); return 0, nil }, hangupFn: func(uintptr) error { t.Fatal("unowned hangup"); return nil }}
	if _, err := connect(context.Background(), testConfig(), d); err == nil {
		t.Fatal("accepted unsafe profile")
	}
}

func TestConnectedAndManualDisconnect(t *testing.T) {
	disconnected, closed := false, false
	d := fakeDriver{
		dialFn: func(Config) (uintptr, error) { return 9, nil },
		statusFn: func(uintptr) (connectionState, error) {
			if closed {
				return connectionState{}, errInvalidHandle
			}
			if disconnected {
				return connectionState{state: stateDisconnected}, nil
			}
			return connectionState{state: stateConnected}, nil
		},
		hangupFn: func(uintptr) error { closed = true; return nil },
	}
	s, err := connect(context.Background(), testConfig(), d)
	if err != nil {
		t.Fatal(err)
	}
	disconnected = true
	if err := s.Wait(context.Background()); err == nil || err.Error() != "ikev2_disconnected" {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil || !closed {
		t.Fatal(err)
	}
}

func TestCleanupFailureOverridesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := fakeDriver{dialFn: func(Config) (uintptr, error) { cancel(); return 1, nil }, hangupFn: func(uintptr) error { return errors.New("access denied") }}
	if _, err := connect(ctx, testConfig(), d); err == nil || err.Error() != "ikev2_cleanup_failed" {
		t.Fatal(err)
	}
}

func TestCloseWaitsForInvalidHandleAndIsConcurrentSafe(t *testing.T) {
	var mu sync.Mutex
	count, hangups := 0, 0
	d := fakeDriver{
		hangupFn: func(uintptr) error { mu.Lock(); defer mu.Unlock(); hangups++; return nil },
		statusFn: func(uintptr) (connectionState, error) {
			mu.Lock()
			defer mu.Unlock()
			count++
			if count > 2 {
				return connectionState{}, errInvalidHandle
			}
			return connectionState{state: stateDisconnected}, nil
		},
	}
	s := &Session{driver: d, handle: 3, interval: time.Millisecond, cleanupTimeout: time.Second}
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if hangups != 1 || count != 3 {
		t.Fatal(hangups, count)
	}
}

func TestCleanupTimeoutAndZeroHandle(t *testing.T) {
	d := fakeDriver{hangupFn: func(uintptr) error { return nil }, statusFn: func(uintptr) (connectionState, error) { return connectionState{state: stateDisconnected}, nil }}
	s := &Session{driver: d, handle: 3, interval: time.Millisecond, cleanupTimeout: 3 * time.Millisecond}
	if err := s.Close(); err == nil || err.Error() != "ikev2_cleanup_timeout" {
		t.Fatal(err)
	}
	d = fakeDriver{dialFn: func(Config) (uintptr, error) { return 0, errors.New("dial failed") }, hangupFn: func(uintptr) error { t.Fatal("zero handle hangup"); return nil }}
	if _, err := connect(context.Background(), testConfig(), d); err == nil {
		t.Fatal("accepted zero handle")
	}
}

func TestConfigRejectsAmbiguousIdentities(t *testing.T) {
	for _, name := range []string{"127.0.0.1", "localhost", "vpn.example.com.", "vpn.example.com:500", "https://vpn.example.com", "a..example", "-vpn.example", "vpn.example\x00.com"} {
		c := testConfig()
		c.ServerName = name
		if c.Validate() == nil {
			t.Errorf("accepted %q", name)
		}
	}
	for _, name := range []string{"", " VPN", "VPN\n", "VPN\\other", "[VPN]"} {
		c := testConfig()
		c.WindowsProfile = name
		if c.Validate() == nil {
			t.Errorf("accepted %q", name)
		}
	}
}
