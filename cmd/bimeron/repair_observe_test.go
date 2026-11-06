package main

import (
	"context"
	"errors"
	"testing"
)

func TestRepairTransitionObservesUntilStable(t *testing.T) {
	reads := 0
	if err := observeRepairTransition(context.Background(), func(context.Context) (bool, error) { reads++; return reads == 2, nil }); err != nil || reads != 2 {
		t.Fatal(reads, err)
	}
}
func TestRepairTransitionStopsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reads := 0
	err := observeRepairTransition(ctx, func(context.Context) (bool, error) { reads++; cancel(); return false, nil })
	if !errors.Is(err, context.Canceled) || reads != 1 {
		t.Fatal(reads, err)
	}
}
func TestRepairTransitionDoesNotRetryInspectionErrors(t *testing.T) {
	reads := 0
	failure := errors.New("access refused")
	err := observeRepairTransition(context.Background(), func(context.Context) (bool, error) { reads++; return false, failure })
	if !errors.Is(err, failure) || reads != 1 {
		t.Fatal(reads, err)
	}
}
