package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConditionalRecoveryOnlyRemovesExactOwnedRules(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hold")
	for _, tc := range []struct {
		name, expected, installed string
		pending, unreadable       bool
		want                      string
		effects                   int
	}{
		{"inspect", "", "own", false, false, "eligible", 0},
		{"matching", "own", "own", false, false, "recovered", 1},
		{"stale", "old", "own", false, false, "conflict", 0},
		{"another owner", "own", "foreign", false, false, "conflict", 0},
		{"incomplete network cleanup", "own", "own", true, false, "unknown", 0},
		{"unreadable network state", "own", "own", false, true, "unknown", 0},
		{"existing update marker", "own", "own", false, false, "conflict", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "existing update marker" {
				if err := os.WriteFile(marker, []byte("invalid or pending"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			effects := 0
			_, result := recoverOwnedRules(context.Background(), tc.expected, "own", marker, func() (string, error) { return tc.installed, nil },
				func(context.Context) (bool, error) {
					if tc.unreadable {
						return false, errors.New("unknown")
					}
					return tc.pending, nil
				},
				func(g string) error {
					if g != "own" {
						t.Fatal(g)
					}
					effects++
					return nil
				})
			if result != tc.want || effects != tc.effects {
				t.Fatal(result, effects)
			}
		})
	}
}
