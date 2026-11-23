//go:build windows

package core

import (
	"context"
	"errors"
	"testing"
)

func TestFinalizeHeldNetworkCommitBoundary(t *testing.T) {
	for _, stage := range []string{"initial", "cleanup", "stale", "delete", "receipt", "success"} {
		t.Run(stage, func(t *testing.T) {
			held, recorded := true, false
			verifies := 0
			failure := errors.New("injected")
			err := finalizeHeldNetwork(context.Background(), func() error {
				verifies++
				if verifies == 1 && stage == "initial" || verifies == 2 && stage == "stale" {
					return failure
				}
				return nil
			}, func(context.Context) error {
				if stage == "cleanup" {
					return failure
				}
				return nil
			}, func() error {
				if verifies != 2 {
					t.Fatal("missing revalidation")
				}
				if stage == "delete" {
					return failure
				}
				held = false
				return nil
			}, func() error {
				if stage == "receipt" {
					return failure
				}
				recorded = true
				return nil
			})
			if (err == nil) != (stage == "success") || recorded != (stage == "success") || held != (stage != "receipt" && stage != "success") {
				t.Fatalf("err=%v held=%v recorded=%v", err, held, recorded)
			}
		})
	}
}
