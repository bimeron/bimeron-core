//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxSourceSwapBeforeElevationIsRejected(t *testing.T) {
	dir := t.TempDir()
	source, staged := filepath.Join(dir, "download"), filepath.Join(dir, "protected.update-new")
	want := sha256.Sum256([]byte("verified"))
	if err := os.WriteFile(source, []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("swapped"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, source); err != nil {
		t.Fatal(err)
	}
	if err := stageVerifiedUpdate(source, staged, hex.EncodeToString(want[:]), copyLinuxServiceFile); err == nil {
		t.Fatal("swapped source accepted")
	}
}
