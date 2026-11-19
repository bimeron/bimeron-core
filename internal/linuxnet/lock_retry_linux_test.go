//go:build linux

package linuxnet

import (
	"errors"
	"testing"
)

// An owner retries a briefly held session lock a bounded number of times.
func TestLockRetryIsBounded(t *testing.T) {
	busy := errors.New("another Bimeron owner is active")
	attempts := 0
	release, err := lockRetry(func() (func(), error) {
		attempts++
		if attempts < 3 {
			return nil, busy
		}
		return func() {}, nil
	}, 5, 0)
	if err != nil || release == nil || attempts != 3 {
		t.Fatal("lock taken after a momentary holder", err, attempts)
	}
	attempts = 0
	if _, err := lockRetry(func() (func(), error) { attempts++; return nil, busy }, 5, 0); !errors.Is(err, busy) || attempts != 5 {
		t.Fatal("held lock retried without bound", err, attempts)
	}
}
