package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestServiceUpdateStopFailureRestoresPriorState(t *testing.T) {
	for _, wasRunning := range []bool{false, true} {
		for _, stopped := range []bool{false, true} {
			t.Run(fmtState(wasRunning, stopped), func(t *testing.T) {
				dir := t.TempDir()
				target := filepath.Join(dir, "service")
				if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
					t.Fatal(err)
				}
				parent, cancel := context.WithCancel(context.Background())
				rollback, done := updateRollbackContext(parent)
				defer done()
				running := wasRunning
				failure := errors.New("stop observation failed")
				restarted := false
				err := runServiceUpdate(wasRunning, func() error {
					if stopped {
						running = false
					}
					cancel()
					return failure
				}, func() error {
					t.Fatal("replacement ran after stop refusal")
					return nil
				}, func() error {
					if err := rollback().Err(); err != nil {
						return err
					}
					restarted, running = true, true
					return nil
				})
				if !errors.Is(err, failure) || running != wasRunning || restarted != wasRunning {
					t.Fatalf("err=%v running=%v restarted=%v", err, running, restarted)
				}
				data, err := os.ReadFile(target)
				if err != nil || string(data) != "original" {
					t.Fatalf("original changed: %q %v", data, err)
				}
			})
		}
	}
}

func fmtState(running, stopped bool) string {
	if running {
		if stopped {
			return "running/stop-completed"
		}
		return "running/stop-not-completed"
	}
	if stopped {
		return "stopped/stop-completed"
	}
	return "stopped/stop-not-completed"
}

func TestServiceUpdateStopAndRestartErrorsPreserved(t *testing.T) {
	stopErr, restartErr := errors.New("stop failed"), errors.New("restart failed")
	err := runServiceUpdate(true, func() error { return stopErr }, func() error { t.Fatal("replace"); return nil }, func() error { return restartErr })
	if !errors.Is(err, stopErr) || !errors.Is(err, restartErr) {
		t.Fatal(err)
	}
}

func TestServiceUpdateBackupRefusalRestoresPriorState(t *testing.T) {
	for _, wasRunning := range []bool{false, true} {
		dir := t.TempDir()
		target, staged, backup := filepath.Join(dir, "service"), filepath.Join(dir, "new"), filepath.Join(dir, "old")
		for path, data := range map[string]string{target: "original", staged: "candidate", backup: "retained"} {
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
		}
		running := wasRunning
		err := runServiceUpdate(wasRunning, func() error { running = false; return nil }, func() error {
			return replaceServiceExecutable(target, staged, backup, func() error { t.Fatal("activate"); return nil }, func() error { t.Fatal("deactivate"); return nil })
		}, func() error { running = true; return nil })
		if err == nil || running != wasRunning {
			t.Fatalf("err=%v running=%v", err, running)
		}
		data, readErr := os.ReadFile(target)
		if readErr != nil || string(data) != "original" {
			t.Fatalf("original changed: %q %v", data, readErr)
		}
	}
}
