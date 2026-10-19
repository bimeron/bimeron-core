package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestServiceExecutableUpdateAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[fail], func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "core")
			staged := target + ".new"
			backup := target + ".old"
			if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(staged, []byte("new"), 0600); err != nil {
				t.Fatal(err)
			}
			err := replaceServiceExecutable(target, staged, backup, func() error {
				if fail {
					return errors.New("startup failure")
				}
				return nil
			}, func() error { return nil })
			data, e := os.ReadFile(target)
			if e != nil {
				t.Fatal(e)
			}
			if fail {
				if err == nil || string(data) != "old" {
					t.Fatal(err, string(data))
				}
			} else {
				if err != nil || string(data) != "new" {
					t.Fatal(err, string(data))
				}
			}
			if _, err := os.Stat(backup); !os.IsNotExist(err) {
				t.Fatal("backup not cleaned")
			}
		})
	}
}
func TestFailedStopRetainsUpdateBackup(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "core")
	staged := target + ".new"
	backup := target + ".old"
	os.WriteFile(target, []byte("old"), 0600)
	os.WriteFile(staged, []byte("new"), 0600)
	err := replaceServiceExecutable(target, staged, backup, func() error { return errors.New("start") }, func() error { return errors.New("stop") })
	data, e := os.ReadFile(backup)
	if err == nil || e != nil || string(data) != "old" {
		t.Fatal("working backup lost", err, e)
	}
}

func TestMissingStagedExecutableRestoresOriginal(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "core")
	backup := target + ".old"
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	err := replaceServiceExecutable(target, target+".missing", backup, func() error { t.Fatal("activated missing binary"); return nil }, func() error { return nil })
	data, e := os.ReadFile(target)
	if !errors.Is(err, errUpdateRolledBack) || e != nil || string(data) != "old" {
		t.Fatal(err, e, string(data))
	}
}
