//go:build windows

package main

import (
	"context"
	"debug/buildinfo"
	"debug/pe"
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

func waitServiceState(s *mgr.Service, want svc.State) error {
	return waitServiceStateContext(context.Background(), s, want)
}
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
func stopUpdateService(s *mgr.Service) error {
	return stopUpdateServiceContext(context.Background(), s)
}
func stopUpdateServiceContext(ctx context.Context, s *mgr.Service) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped && status.State != svc.StopPending {
		if _, err = s.Control(svc.Stop); err != nil {
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
	if !windowsServiceExitClean(status) || status.ProcessId != 0 {
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
	defer os.Remove(staged)
	if err = stageVerifiedUpdate(expect.source, staged, expect.sha256, copyServiceFile); err != nil {
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
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Running && status.State != svc.Stopped {
		return fmt.Errorf("wait for stable service state before updating")
	}
	wasRunning := status.State == svc.Running
	if err = stopUpdateServiceContext(ctx, s); err != nil {
		return err
	}
	stopped, err := s.Query()
	if err != nil {
		return err
	}
	if stopped.Win32ExitCode != 0 {
		return fmt.Errorf("service cleanup failed; run doctor/recover before update")
	}
	rollbackContext, releaseRollback := updateRollbackContext(ctx)
	defer releaseRollback()
	err = replaceServiceExecutable(target, staged, backup, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return activateServiceUpdate(ctx, wasRunning, forceActivate, func() error { return s.Start() }, func() error {
			if err := waitServiceStateContext(ctx, s, svc.Running); err != nil {
				return err
			}
			return waitUpdatedServiceContext(ctx, expect.version)
		})
	}, func() error { return stopUpdateServiceContext(rollbackContext(), s) })
	err = restorePreviousService(err, wasRunning, func() error {
		if err := rollbackContext().Err(); err != nil {
			return err
		}
		if err := s.Start(); err != nil {
			return err
		}
		return waitServiceStateContext(rollbackContext(), s, svc.Running)
	})
	if err != nil {
		return err
	}
	fmt.Println("Service updated; owner and startup settings preserved. VPN remains disconnected.")
	return nil
}
