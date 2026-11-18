//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
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
	if err := copyLinuxUpdateSource(source, staged); err == nil {
		t.Fatal("existing staged file replaced")
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
