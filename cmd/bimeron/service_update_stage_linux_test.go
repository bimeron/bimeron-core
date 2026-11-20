//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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
	if err := stageVerifiedUpdate(source, staged, hex.EncodeToString(want[:]), copyLinuxUpdateSource); err == nil {
		t.Fatal("swapped source accepted")
	}
}

func TestLinuxUpdateSourceIsStagedPrivately(t *testing.T) {
	dir := t.TempDir()
	source, staged := filepath.Join(dir, "download"), filepath.Join(dir, "protected.update-new")
	if err := os.WriteFile(source, []byte("verified"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := copyLinuxUpdateSource(source, staged); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(staged)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("staged permissions", info, err)
	}
}

func TestLinuxStaleStagedUpdateIsReplaced(t *testing.T) {
	dir := t.TempDir()
	source, staged := filepath.Join(dir, "download"), filepath.Join(dir, "protected.update-new")
	if err := os.WriteFile(source, []byte("verified"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("left by an interrupted update"), 0755); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("verified"))
	if err := stageVerifiedUpdate(source, staged, hex.EncodeToString(want[:]), copyLinuxUpdateSource); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(staged)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("staged permissions", info, err)
	}
}

func TestLinuxUpdateSourceRejectsLinksAndNonFiles(t *testing.T) {
	dir := t.TempDir()
	target, link, staged := filepath.Join(dir, "target"), filepath.Join(dir, "link"), filepath.Join(dir, "staged")
	if err := os.WriteFile(target, []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{link, dir, "/dev/null"} {
		if err := copyLinuxUpdateSource(source, staged); err == nil {
			t.Fatal("accepted", source)
		}
	}
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Fatal("staged file created", err)
	}
	if err := copyLinuxUpdateSource(link, staged); !errors.Is(err, errUpdateSourceLink) {
		t.Fatal("link source", err)
	}
}

// TestLinuxUpdateSourceLoopIsNotReportedAsLink resolves a path through a
// directory symlink loop, which fails with ELOOP although the final
// component is not a link.
func TestLinuxUpdateSourceLoopIsNotReportedAsLink(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	err := copyLinuxUpdateSource(filepath.Join(a, "bimeron"), filepath.Join(dir, "staged"))
	if err == nil || errors.Is(err, errUpdateSourceLink) || !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("source through a symlink loop: %v", err)
	}
}

// A FIFO without a writer would block a plain open; the source must be
// rejected promptly instead.
func TestLinuxUpdateSourceRejectsFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo, staged := filepath.Join(dir, "fifo"), filepath.Join(dir, "staged")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	done := make(chan error, 1)
	go func() { done <- copyLinuxUpdateSource(fifo, staged) }()
	select {
	case err := <-done:
		if !errors.Is(err, errUpdateSourceNotRegular) {
			t.Fatal("FIFO source", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FIFO source blocked")
	}
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Fatal("staged file created", err)
	}
}

func TestLinuxUpdateSourceSizeAndDigestFailuresRemoveStaged(t *testing.T) {
	dir := t.TempDir()
	source, staged := filepath.Join(dir, "download"), filepath.Join(dir, "protected.update-new")
	if err := os.WriteFile(source, []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("verified"))
	defer func(limit int64) { maxUpdateSourceSize = limit }(maxUpdateSourceSize)
	maxUpdateSourceSize = 7
	if err := stageVerifiedUpdate(source, staged, hex.EncodeToString(want[:]), copyLinuxUpdateSource); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatal("oversized source", err)
	}
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Fatal("oversized staged file kept", err)
	}
	maxUpdateSourceSize = 8
	if err := stageVerifiedUpdate(source, staged, strings.Repeat("0", 64), copyLinuxUpdateSource); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Fatal("mismatched staged file kept", err)
	}
	if err := stageVerifiedUpdate(source, staged, hex.EncodeToString(want[:]), copyLinuxUpdateSource); err != nil {
		t.Fatal(err)
	}
}
