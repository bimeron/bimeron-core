//go:build windows

package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestRestoreClaimAdmitsOnlyOneConcurrentCommit(t *testing.T) {
	dir := t.TempDir()
	id := strings.Repeat("a", 32)
	start := make(chan struct{})
	results := make(chan string, 8)
	for n := 0; n < cap(results); n++ {
		go func(instance string) {
			<-start
			if publishRestoreRecord(dir, id, "claim", instance) != nil {
				results <- ""
				return
			}
			results <- instance
		}(fmt.Sprintf("%032x", n+1))
	}
	close(start)
	var winner string
	for n := 0; n < cap(results); n++ {
		if s := <-results; s != "" {
			if winner != "" {
				t.Fatal("two claims")
			}
			winner = s
		}
	}
	var persisted string
	if err := readRestoreRecord(dir, id, "claim", &persisted); err != nil || winner == "" || winner != persisted {
		t.Fatalf("claim %q winner %q err %v", persisted, winner, err)
	}
	if err := publishRestoreRecord(dir, id, "claim", "replacement"); err == nil {
		t.Fatal("replayed claim")
	}
}
