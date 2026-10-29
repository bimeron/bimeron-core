package systemvpn

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestObservedFailedStartupReportsIndependentCleanup(t *testing.T) {
	closed := false
	states := []string{}
	d := fakeDriver{dialFn: func(Config) (uintptr, error) { return 42, errors.New("dial failure") }, hangupFn: func(uintptr) error { closed = true; return nil }, statusFn: func(uintptr) (connectionState, error) {
		if closed {
			return connectionState{}, errInvalidHandle
		}
		return connectionState{}, nil
	}}
	if _, err := connectObserved(context.Background(), testConfig(), d, func(s string) { states = append(states, s) }); err == nil {
		t.Fatal("failed dial accepted")
	}
	if !reflect.DeepEqual(states, []string{"pending", "succeeded"}) {
		t.Fatal(states)
	}
}
