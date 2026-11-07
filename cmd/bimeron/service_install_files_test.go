package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveServiceFilesToleratesPartialRemoval(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "unrelated.txt")
	for _, path := range []string{filepath.Join(dir, "wintun.dll"), keep} {
		if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeServiceFiles(dir); err != nil {
		t.Fatal("partial installation was not removed:", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "wintun.dll")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("stale service file kept:", err)
	}
	if _, err := os.Lstat(keep); err != nil {
		t.Fatal("unrelated file removed:", err)
	}
	if err := removeServiceFiles(dir); err != nil {
		t.Fatal("repeated removal failed:", err)
	}
}

func TestRemoveServiceFilesRefusesNonRegularObjects(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "bimeron.exe"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wintun.dll"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	err := removeServiceFiles(dir)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatal("non-regular object accepted:", err)
	}
	if _, statErr := os.Lstat(filepath.Join(dir, "bimeron.exe")); statErr != nil {
		t.Fatal("non-regular object removed:", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(dir, "wintun.dll")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatal("remaining regular files were not removed after an error:", statErr)
	}
}

func TestUninstallServiceArtifactsKeepsFilesWhenDeleteFails(t *testing.T) {
	deleteErr := errors.New("access denied")
	called := false
	step := func() error { called = true; return nil }
	if err := uninstallServiceArtifacts(func() error { return deleteErr }, step, step); !errors.Is(err, deleteErr) || called {
		t.Fatal("cleanup continued after the registration delete failed:", err, called)
	}
}

func TestUninstallServiceArtifactsResumesWithoutRegistration(t *testing.T) {
	filesRemoved := false
	missing := func() error { return fs.ErrNotExist }
	if err := uninstallServiceArtifacts(nil, missing, func() error { filesRemoved = true; return nil }); err != nil || !filesRemoved {
		t.Fatal("resumed uninstall did not tolerate a removed event source:", err, filesRemoved)
	}
	eventErr, fileErr := errors.New("event"), errors.New("files")
	err := uninstallServiceArtifacts(nil, func() error { return eventErr }, func() error { return fileErr })
	if !errors.Is(err, eventErr) || !errors.Is(err, fileErr) {
		t.Fatal("cleanup failures were not aggregated:", err)
	}
}
