package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStoppedRepairActivatesBeforeCommittingAndRestoresSidecar(t *testing.T) {
	for _, failReady := range []bool{false, true} {
		t.Run(map[bool]string{false: "ready", true: "rollback"}[failReady], func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "core")
			staged := target + ".new"
			backup := target + ".old"
			dll := filepath.Join(dir, "wintun")
			dllBackup := dll + ".old"
			for p, v := range map[string]string{target: "old-core", staged: "new-core", dll: "new-dll", dllBackup: "old-dll"} {
				if err := os.WriteFile(p, []byte(v), 0600); err != nil {
					t.Fatal(err)
				}
			}
			running := false
			var events []string
			err := replaceServiceExecutable(target, staged, backup, func() error {
				return activateServiceUpdate(context.Background(), false, true, func() error { events = append(events, "start"); running = true; return nil }, func() error {
					events = append(events, "readiness")
					if !running {
						t.Fatal("readiness without start")
					}
					if failReady {
						return errors.New("readiness failed")
					}
					return nil
				})
			}, func() error { events = append(events, "stop-core"); running = false; return nil })
			err = finishRepairSidecar(err, func(success bool) error {
				if success {
					events = append(events, "commit-dll")
					return os.Remove(dllBackup)
				}
				events = append(events, "restore-dll")
				if running {
					t.Fatal("restored loaded DLL")
				}
				if err := os.Remove(dll); err != nil {
					return err
				}
				return os.Rename(dllBackup, dll)
			}, func() error {
				events = append(events, "confirm-stopped")
				if running {
					return errors.New("still running")
				}
				return nil
			})
			wantCore, wantDLL := "new-core", "new-dll"
			want := []string{"start", "readiness", "commit-dll"}
			if failReady {
				wantCore, wantDLL = "old-core", "old-dll"
				want = []string{"start", "readiness", "stop-core", "confirm-stopped", "restore-dll"}
			}
			if (err != nil) != failReady {
				t.Fatal(err)
			}
			for p, want := range map[string]string{target: wantCore, dll: wantDLL} {
				data, e := os.ReadFile(p)
				if e != nil || string(data) != want {
					t.Fatal(p, string(data), e)
				}
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatal(events)
			}
		})
	}
}
func TestLegacyStoppedUpdateDoesNotStart(t *testing.T) {
	if err := activateServiceUpdate(context.Background(), false, false, func() error { t.Fatal("legacy stopped update started"); return nil }, func() error { t.Fatal("legacy stopped update probed"); return nil }); err != nil {
		t.Fatal(err)
	}
}
func TestSidecarRollbackKeepsBackupWhenStopFails(t *testing.T) {
	finalized := false
	err := finishRepairSidecar(errors.New("activation failed"), func(bool) error { finalized = true; return nil }, func() error { return errors.New("cleanup unconfirmed") })
	if err == nil || finalized {
		t.Fatal("unsafe sidecar rollback")
	}
}
