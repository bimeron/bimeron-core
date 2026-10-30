package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"bimeron/core"
	"bimeron/internal/control"
	"bimeron/internal/nativeenrollment"
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

func TestFailedIPCHealthCheckRestoresOldExecutable(t *testing.T) {
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
	running := false // old service has been stopped before the executable swap
	err := replaceServiceExecutable(target, staged, backup, func() error {
		running = true
		return validateUpdatedHello(control.Response{Version: control.Version, Core: &core.BuildDetails{Version: "wrong"}}, "expected")
	}, func() error { running = false; return nil })
	if !errors.Is(err, errUpdateRolledBack) || running {
		t.Fatal("new service not stopped for rollback", err)
	}
	err = restorePreviousService(err, true, func() error { running = true; return nil })
	data, readErr := os.ReadFile(target)
	if !errors.Is(err, errUpdateRolledBack) || readErr != nil || string(data) != "old" || !running {
		t.Fatal("previous running state not restored", err, readErr)
	}
}

func TestStoppedServiceUpdateRemainsStopped(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "core")
	staged := target + ".new"
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	running := false
	err := replaceServiceExecutable(target, staged, target+".old", func() error { return nil }, func() error { running = false; return nil })
	data, readErr := os.ReadFile(target)
	if err != nil || readErr != nil || string(data) != "new" || running {
		t.Fatal("stopped service state changed", err, readErr)
	}
}

// This ledger surrounds the real helpers. Callbacks are observations, never SCM
// execution or restored IPC health evidence; no production caller imports it.
func TestPendingLedgerAroundActualUpdate(t *testing.T) {
	for _, scenario := range []string{"success-running", "success-stopped", "activation", "health", "stop-failure", "remove-failure", "rename-failure", "restart-failure", "restore-stopped", "crash-activation", "crash-after-swap", "crash-after-restore"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "core")
			staged := target + ".new"
			backup := target + ".old"
			write := func(path, body string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			read := func(path, want string) {
				t.Helper()
				b, err := os.ReadFile(path)
				if err != nil || string(b) != want {
					t.Fatalf("%s: %q %v", path, b, err)
				}
			}
			write(target, "old")
			write(staged, "new")
			record := nativeenrollment.Record{Phase: nativeenrollment.Pending, Generation: 1, Installation: [16]byte{1}, Operation: [16]byte{2}}
			encoded, encodeErr := nativeenrollment.Encode(record)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			pending := [64]byte(encoded)
			original := pending
			events := []string{"pending", "staged-verified", "old-stopped"}
			running := scenario != "success-stopped" && scenario != "restore-stopped"
			failure := errors.New("observed failure")
			crash := errors.New("simulated updater death")
			var err error
			func() {
				defer func() {
					if p := recover(); p != nil {
						if p != crash {
							panic(p)
						}
						events = append(events, "updater-lost")
					}
				}()
				err = replaceServiceExecutable(target, staged, backup, func() error {
					events = append(events, "swapped")
					read(target, "new")
					read(backup, "old")
					if scenario == "crash-activation" {
						panic(crash)
					}
					if !running {
						if scenario == "restore-stopped" {
							return failure
						}
						return nil
					}
					events = append(events, "candidate-start")
					if scenario == "activation" {
						return failure
					}
					events = append(events, "candidate-IPC")
					if scenario == "success-running" || scenario == "crash-after-swap" {
						return nil
					}
					return validateUpdatedHello(control.Response{}, "expected")
				}, func() error {
					events = append(events, "candidate-stop")
					if scenario == "stop-failure" {
						return failure
					}
					if scenario == "remove-failure" || scenario == "rename-failure" {
						if e := os.Remove(target); e != nil {
							t.Fatal(e)
						}
						if e := os.Mkdir(target, 0700); e != nil {
							t.Fatal(e)
						}
						if scenario == "remove-failure" {
							write(filepath.Join(target, "block"), "block")
						} else {
							// Removing an empty target directory succeeds, then the missing backup
							// makes the actual restore rename fail. Retain its bytes separately.
							if e := os.Rename(backup, backup+".retained"); e != nil {
								t.Fatal(e)
							}
						}
					}
					return nil
				})
				events = append(events, "replace-return")
				if scenario == "crash-after-swap" {
					panic(crash)
				}
				err = restorePreviousService(err, running, func() error {
					events = append(events, "restore-start")
					read(target, "old")
					if scenario == "restart-failure" {
						return failure
					}
					events = append(events, "restored-SCM-running")
					return nil // Actual Windows callback has no restored IPC probe.
				})
				if scenario == "crash-after-restore" {
					panic(crash)
				}
			}()
			if pending != original {
				t.Fatal("pending changed")
			}
			if scenario == "success-running" || scenario == "success-stopped" || scenario == "crash-after-swap" {
				read(target, "new")
			} else if scenario == "crash-activation" || scenario == "stop-failure" {
				read(target, "new")
				read(backup, "old")
			} else if scenario == "remove-failure" {
				read(backup, "old")
			} else if scenario == "rename-failure" {
				read(backup+".retained", "old")
			} else {
				read(target, "old")
				if !errors.Is(err, errUpdateRolledBack) {
					t.Fatal(err)
				}
			}
			if scenario == "restart-failure" && !errors.Is(err, failure) {
				t.Fatal("restart failure lost", err)
			}
			if !running {
				for _, event := range events {
					if event == "candidate-start" || event == "candidate-IPC" || event == "restore-start" {
						t.Fatal(events)
					}
				}
			}
			// Check ordering against actual callback boundaries, not a mirrored swap.
			positions := map[string]int{}
			for i, event := range events {
				positions[event] = i
			}
			for _, pair := range [][2]string{{"pending", "swapped"}, {"swapped", "candidate-start"}, {"candidate-start", "candidate-IPC"}, {"candidate-IPC", "candidate-stop"}, {"candidate-stop", "restore-start"}, {"restore-start", "restored-SCM-running"}} {
				a, okA := positions[pair[0]]
				b, okB := positions[pair[1]]
				if okA && okB && a >= b {
					t.Fatal(events)
				}
			}
		})
	}
}

func TestLegacyWindowsRestoreObservationSource(t *testing.T) {
	// Inspect the actual callback; local fake observations cannot prove SCM behavior.
	file, err := parser.ParseFile(token.NewFileSet(), "service_update_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name, ok := call.Fun.(*ast.Ident)
		if !ok || name.Name != "restorePreviousService" {
			return true
		}
		found = true
		callback, ok := call.Args[2].(*ast.FuncLit)
		if !ok {
			t.Fatal("restore callback changed")
		}
		calls := []string{}
		ast.Inspect(callback, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch f := c.Fun.(type) {
			case *ast.Ident:
				calls = append(calls, f.Name)
			case *ast.SelectorExpr:
				calls = append(calls, f.Sel.Name)
			}
			return true
		})
		if len(calls) != 2 || calls[0] != "Start" || calls[1] != "waitServiceState" {
			t.Fatalf("legacy restore observation changed: %v", calls)
		}
		return false
	})
	if !found {
		t.Fatal("actual restore callback not found")
	}
}
