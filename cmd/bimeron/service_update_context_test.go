package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUpdateRollbackRetainsIndependentSharedBudget(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	cleanup, release := updateRollbackContext(parent)
	defer release()
	first := cleanup()
	if first.Err() != nil {
		t.Fatal("rollback inherited canceled operation")
	}
	if first != cleanup() {
		t.Fatal("rollback renewed its budget")
	}
	deadline, ok := first.Deadline()
	if !ok || time.Until(deadline) > 30*time.Second {
		t.Fatal("unbounded rollback")
	}
	release()
	if !errors.Is(first.Err(), context.Canceled) {
		t.Fatal("cleanup context retained")
	}
}
func TestUpdatedServiceHonorsCanceledContextWithoutProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitUpdatedServiceContext(ctx, "test"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
