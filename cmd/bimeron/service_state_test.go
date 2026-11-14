package main

import "testing"

func TestFormatServiceStateNamesSCMStates(t *testing.T) {
	for code, want := range map[uint32]string{1: "1 (stopped)", 4: "4 (running)", 7: "7 (paused)", 99: "99 (unknown)"} {
		if got := formatServiceState(code); got != want {
			t.Fatalf("state %d: got %q, want %q", code, got, want)
		}
	}
}
