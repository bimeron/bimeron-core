//go:build windows

package main

import (
	"bimeron/core"
	"bimeron/internal/control"
	"context"
	"crypto/rand"
	"debug/buildinfo"
	"debug/pe"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const serviceDescription = "VPN core and local control"

func waitServiceStateContext(ctx context.Context, s *mgr.Service, want svc.State) error {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		status, err := s.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		if want == svc.Running && status.State == svc.Stopped {
			return fmt.Errorf("updated service failed to start")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("service state change timed out")
}
func stopUpdateServiceContext(ctx context.Context, s *mgr.Service, cmd svc.Cmd) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped && status.State != svc.StopPending {
		if _, err = s.Control(cmd); err != nil {
			return err
		}
	}
	if err := waitServiceStateContext(ctx, s, svc.Stopped); err != nil {
		return err
	}
	status, err = s.Query()
	if err != nil {
		return err
	}
	return windowsUpdateCleanupProven(status)
}

func windowsUpdateCleanupProven(status svc.Status) error {
	if status.State != svc.Stopped || !windowsServiceExitClean(status) || status.ProcessId != 0 {
		return fmt.Errorf("service cleanup unconfirmed")
	}
	return nil
}
func updateWindowsService(s *mgr.Service, expect updateExpectation) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return updateWindowsServiceContext(ctx, s, expect)
}
func updateWindowsServiceContext(ctx context.Context, s *mgr.Service, expect updateExpectation) error {
	return updateWindowsServiceMode(ctx, s, expect, false)
}
func updateWindowsServiceMode(ctx context.Context, s *mgr.Service, expect updateExpectation, forceActivate bool) error {
	return updateWindowsServiceGuarded(ctx, s, expect, forceActivate, nil)
}
func updateWindowsServiceGuarded(ctx context.Context, s *mgr.Service, expect updateExpectation, forceActivate bool, guard *restoreIntent) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Serialize installers without sharing the VPN session mutex.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name, _ := windows.UTF16PtrFromString(`Global\BimeronCoreUpdate`)
	lock, err := windows.CreateMutex(nil, false, name)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return err
	}
	defer windows.CloseHandle(lock)
	result, err := windows.WaitForSingleObject(lock, 0)
	if err != nil || (result != windows.WAIT_OBJECT_0 && result != windows.WAIT_ABANDONED) {
		return fmt.Errorf("another service update is running")
	}
	defer windows.ReleaseMutex(lock)
	config, err := s.Config()
	if err != nil {
		return err
	}
	argv, err := windows.DecomposeCommandLine(config.BinaryPathName)
	if err != nil || len(argv) != 4 || argv[1] != "service" || argv[2] != "run" {
		return fmt.Errorf("unexpected installed service command")
	}
	if _, err = windows.StringToSid(argv[3]); err != nil {
		return fmt.Errorf("invalid installed service owner")
	}
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "Bimeron Core")
	target := filepath.Join(dir, "bimeron.exe")
	if !strings.EqualFold(filepath.Clean(argv[0]), target) {
		return fmt.Errorf("unexpected installation path")
	}
	if err = protectServiceDir(dir); err != nil {
		return err
	}
	installed, err := os.Lstat(target)
	if err != nil {
		return err
	}
	if !installed.Mode().IsRegular() {
		return fmt.Errorf("unsafe installed service executable")
	}
	updater, err := os.Executable()
	if err != nil {
		return err
	}
	if strings.EqualFold(filepath.Clean(updater), target) {
		return fmt.Errorf("run service update from the trusted GUI package core, not the installed service")
	}
	if strings.EqualFold(filepath.Clean(expect.source), target) {
		return fmt.Errorf("update source is the installed service")
	}
	currentPE, err := pe.Open(target)
	if err != nil {
		return err
	}
	machine := currentPE.Machine
	currentPE.Close()
	staged := target + ".update-new"
	backup := target + ".update-old"
	if _, err = os.Lstat(backup); !os.IsNotExist(err) {
		return fmt.Errorf("previous update backup present; resolve it before retrying")
	}
	defer removeStagedUpdate(staged, &err)
	if err = stageVerifiedUpdate(expect.source, staged, expect.sha256, copyUpdateSource); err != nil {
		return err
	}
	info, err := buildinfo.ReadFile(staged)
	if err != nil || info.Path != "bimeron/cmd/bimeron" {
		return fmt.Errorf("invalid staged update binary")
	}
	newPE, err := pe.Open(staged)
	if err != nil {
		return err
	}
	newMachine := newPE.Machine
	newPE.Close()
	if machine != newMachine {
		return fmt.Errorf("update architecture differs from installed service")
	}
	if err = inheritServiceFileACL(staged); err != nil {
		return err
	}
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Running && status.State != svc.Stopped {
		return fmt.Errorf("wait for stable service state before updating")
	}
	wasRunning := status.State == svc.Running
	if guard != nil && !wasRunning {
		return fmt.Errorf("held restore requires running source")
	}
	if !wasRunning {
		if expect.keepKillSwitch {
			fmt.Println("warning: the service is stopped; no running session can keep kill switch protection during the update")
		}
		if err := windowsUpdateCleanupProven(status); err != nil {
			return err
		}
	}
	rollbackContext, releaseRollback := updateRollbackContext(ctx)
	defer releaseRollback()
	kept := false
	var transaction, profile string
	marker := core.UpdateHold{Path: filepath.Join(dir, updateHoldFile)}
	if wasRunning && expect.keepKillSwitch && !forceActivate {
		var message string
		answer, prepareErr := requestUpdateHold(ctx, s)
		kept, message, err = updateHoldMessage(answer, prepareErr)
		transaction = answer.UpdateTransaction
		if guard != nil {
			if prepareErr != nil || transaction == "" || answer.Instance != guard.Request.Instance || answer.Status.KillSwitch != core.KillSwitchResidual || answer.Status.ResidualReason != core.ResidualUpdate {
				return fmt.Errorf("held restore preparation changed")
			}
			a, e := control.CallService(ctx, control.Request{Command: "status"})
			image, imageErr := regularFileSHA256(target)
			if e != nil || imageErr != nil || image != guard.InitialSHA256 || a.Instance != guard.Request.Instance || !a.Status.HasUpdateHold() || a.Status.ResidualProfile != guard.Request.Profile || a.Status.ResidualGeneration != guard.Request.Generation {
				return fmt.Errorf("held restore identity changed")
			}
		}
		if err != nil {
			return err
		}
		if message != "" {
			fmt.Println(message)
		}
	}
	err = runServiceUpdate(wasRunning, func() error {
		if transaction == "" {
			return stopUpdateServiceContext(ctx, s, svc.Stop)
		}
		if err := commitUpdateStop(ctx, s, transaction); err != nil {
			return err
		}
		var err error
		profile, err = marker.StopOutcome(transaction)
		if err == nil && kept && profile == "" {
			return fmt.Errorf("prepared protection missing at update stop")
		}
		if guard != nil && profile != guard.Request.Profile {
			return fmt.Errorf("unexpected stopped profile")
		}
		kept = profile != ""
		return err
	}, func() error {
		return replaceServiceExecutable(target, staged, backup, func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return activateServiceUpdate(ctx, wasRunning, forceActivate, func() error { return s.Start() }, func() error {
				if err := waitServiceStateContext(ctx, s, svc.Running); err != nil {
					return err
				}
				if forceActivate {
					return waitUpdatedServiceWithCall(ctx, expect.version, false, func(ctx context.Context, r control.Request) (control.Response, error) {
						state, err := s.Query()
						if err != nil {
							return control.Response{}, err
						}
						if state.State != svc.Running {
							return control.Response{}, fmt.Errorf("service not running")
						}
						return control.CallServiceReadiness(ctx, state.ProcessId, r)
					})
				}
				return waitUpdatedServiceWithCall(ctx, expect.version, kept, func(ctx context.Context, r control.Request) (control.Response, error) {
					a, err := control.CallService(ctx, r)
					if err == nil && kept && r.Command == "status" {
						err = verifyRetainedUpdate(a.Status, profile, marker.TransactionProfile(transaction))
					}
					return a, err
				})
			})
		}, func() error {
			// A client may already have restarted the held profile on the
			// new service; keep that protection across the rollback stop.
			return stopForRollback(expect.keepKillSwitch && !forceActivate, func() (svc.Status, error) {
				state, err := s.Query()
				if err == nil && state.State == svc.Stopped && kept && marker.TransactionProfile(transaction) != profile {
					return state, fmt.Errorf("rollback protection unconfirmed after service exit")
				}
				return state, err
			}, func() (control.Response, error) {
				return requestUpdateHold(rollbackContext(), s)
			}, func(id string, required bool) error {
				if id == "" {
					return stopUpdateServiceContext(rollbackContext(), s, svc.Stop)
				}
				if err := commitUpdateStop(rollbackContext(), s, id); err != nil {
					return err
				}
				profile, err := marker.StopOutcome(id)
				if required && err == nil && profile == "" {
					return fmt.Errorf("rollback protection unconfirmed")
				}
				return err
			})
		})
	}, func() error {
		if err := rollbackContext().Err(); err != nil {
			return err
		}
		// Stop may have failed before sending control, or while stop is pending.
		state, err := s.Query()
		if err != nil {
			return err
		}
		if state.State == svc.Running {
			return nil
		}
		if state.State != svc.Stopped {
			if err := waitServiceStateContext(rollbackContext(), s, svc.Stopped); err != nil {
				return err
			}
		}
		if err := s.Start(); err != nil {
			return err
		}
		return waitServiceStateContext(rollbackContext(), s, svc.Running)
	})
	if err != nil {
		return err
	}
	if kept {
		fmt.Println("Service updated; owner and startup settings preserved. Kill switch protection was kept; start the profile again to reconnect.")
		return nil
	}
	fmt.Println("Service updated; owner and startup settings preserved. VPN remains disconnected.")
	return nil
}

func stopForRollback(keep bool, query func() (svc.Status, error), request func() (control.Response, error), stop func(string, bool) error) error {
	var transaction string
	var required bool
	if keep {
		state, err := query()
		if err != nil {
			return err
		}
		if state.State == svc.Stopped {
			return windowsUpdateCleanupProven(state)
		}
		if state.State != svc.Running {
			return fmt.Errorf("rollback service state is unstable")
		}
		a, err := request()
		if err != nil || a.UpdateTransaction == "" {
			return fmt.Errorf("rollback hold unconfirmed: %v", err)
		}
		required = updateProtectionRequired(a.Status)
		transaction = a.UpdateTransaction
	}
	return stop(transaction, required)
}

// requestUpdateHold asks the running service, over the administrator-only
// readiness pipe bound to the SCM-reported process, to keep kill switch
// protection on the next stop (ADR 0041).
func requestUpdateHold(ctx context.Context, s *mgr.Service) (control.Response, error) {
	status, err := s.Query()
	if err != nil {
		return control.Response{}, err
	}
	if status.State != svc.Running {
		return control.Response{}, fmt.Errorf("service not running")
	}
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return negotiateUpdateHold(func(r control.Request) (control.Response, error) {
		return control.CallServiceReadiness(probe, status.ProcessId, r)
	}, func() (control.Response, error) {
		return control.CallService(probe, control.Request{Command: "capabilities"})
	})
}

func negotiateUpdateHold(call func(control.Request) (control.Response, error), capabilities func() (control.Response, error)) (control.Response, error) {
	hello, err := call(control.Request{Command: "hello"})
	if err != nil || validateRepairHello(hello) != nil {
		return control.Response{}, fmt.Errorf("could not verify readiness hello")
	}
	if !hello.UpdateCommitSupported {
		// Earlier prepare-capable builds arm an ordinary SCM stop. Detect
		// them before issuing a prepare that this updater cannot consume.
		caps, err := capabilities()
		if err != nil || caps.Version != control.Version || caps.Instance != hello.Instance || caps.Capabilities == nil || caps.Capabilities.KillSwitchUpdateHold {
			return control.Response{}, fmt.Errorf("installed service lacks transactional update stop")
		}
	}
	r := control.Request{Command: "prepare_update"}
	if hello.UpdateCommitSupported {
		r.ID = rand.Text()
	}
	answer, err := call(r)
	if answer.Instance != hello.Instance || answer.Version != control.Version {
		return control.Response{}, fmt.Errorf("update preparation identity changed")
	}
	if hello.UpdateCommitSupported {
		if err != nil || answer.ID != r.ID || answer.UpdateTransaction != r.ID {
			return control.Response{}, fmt.Errorf("transactional update preparation unconfirmed")
		}
	} else if err == nil || answer.Error != "invalid_request" || answer.UpdateTransaction != "" {
		return control.Response{}, fmt.Errorf("legacy service preparation unconfirmed")
	}
	return answer, err
}

func commitUpdateStop(ctx context.Context, s *mgr.Service, id string) error {
	state, err := s.Query()
	if err != nil {
		return err
	}
	if state.State != svc.Running {
		return fmt.Errorf("prepared service is no longer running")
	}
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	a, err := control.CallServiceReadiness(probe, state.ProcessId, control.Request{Command: "commit_update", ID: id})
	cancel()
	if a.Version == control.Version && a.Instance != "" && a.ID == id && a.Error != "" {
		return fmt.Errorf("update commit rejected: %s", a.Error)
	}
	// A lost acknowledgement can follow an accepted commit. Observe SCM and
	// let the caller require the exact durable stop receipt before replacing.
	if waitErr := waitServiceStateContext(ctx, s, svc.Stopped); waitErr != nil {
		return errors.Join(fmt.Errorf("update commit outcome unconfirmed"), err, waitErr)
	}
	state, err = s.Query()
	if err != nil {
		return err
	}
	return windowsUpdateCleanupProven(state)
}

func verifyRetainedUpdate(status core.Status, expected, verified string) error {
	if expected != "" && (status.KillSwitch == core.KillSwitchActive || status.KillSwitch == core.KillSwitchHolding) &&
		status.Session != nil && status.Session.ProfileID == expected {
		return nil
	}
	if expected != "" && status.HasUpdateHold() && status.ResidualProfile == expected && verified == expected {
		return nil
	}
	return fmt.Errorf("updated service protection unconfirmed")
}

func updateProtectionRequired(status core.Status) bool {
	return status.KillSwitch == core.KillSwitchActive || status.KillSwitch == core.KillSwitchHolding ||
		status.KillSwitch == core.KillSwitchResidual && status.ResidualReason == core.ResidualUpdate
}

// updateHoldMessage reports whether the installed service keeps kill switch
// protection across the update and what to tell the caller. An installed
// service without the capability rejects the request; the update then
// continues with protection released, as before.
func updateHoldMessage(a control.Response, err error) (bool, string, error) {
	const released = "the kill switch protection is released while the service restarts"
	if err != nil {
		if a.Version == control.Version && a.Instance != "" && a.Error == "invalid_request" {
			return false, "warning: the installed service cannot keep kill switch protection during an update; " + released, nil
		}
		return false, "", fmt.Errorf("could not confirm the kill switch update hold; service stop was not requested: %w", err)
	}
	if updateProtectionRequired(a.Status) {
		return true, "Kill switch protection requested for the update.", nil
	}
	if a.Status.KillSwitch == core.KillSwitchResidual {
		return false, "Residual kill switch protection stays installed during the update.", nil
	}
	return false, "", nil
}
