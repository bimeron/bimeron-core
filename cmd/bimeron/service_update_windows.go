//go:build windows

package main

import (
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

func waitServiceState(s *mgr.Service, want svc.State) error {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
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
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("service state change timed out")
}
func stopUpdateService(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped && status.State != svc.StopPending {
		if _, err = s.Control(svc.Stop); err != nil {
			return err
		}
	}
	return waitServiceState(s, svc.Stopped)
}
func updateWindowsService(s *mgr.Service) error {
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
	source, err := os.Executable()
	if err != nil {
		return err
	}
	if strings.EqualFold(filepath.Clean(source), target) {
		return fmt.Errorf("run service update from the new project binary")
	}
	info, err := buildinfo.ReadFile(source)
	if err != nil || info.Path != "bimeron/cmd/bimeron" {
		return fmt.Errorf("invalid update binary")
	}
	currentPE, err := pe.Open(target)
	if err != nil {
		return err
	}
	machine := currentPE.Machine
	currentPE.Close()
	sourcePE, err := pe.Open(source)
	if err != nil {
		return err
	}
	newMachine := sourcePE.Machine
	sourcePE.Close()
	if machine != newMachine {
		return fmt.Errorf("update architecture differs from installed service")
	}
	staged := target + ".update-new"
	backup := target + ".update-old"
	if _, err = os.Lstat(backup); !os.IsNotExist(err) {
		return fmt.Errorf("previous update backup present; resolve it before retrying")
	}
	if err = copyServiceFile(source, staged); err != nil {
		return err
	}
	defer os.Remove(staged)
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Running && status.State != svc.Stopped {
		return fmt.Errorf("wait for stable service state before updating")
	}
	wasRunning := status.State == svc.Running
	if err = stopUpdateService(s); err != nil {
		return err
	}
	stopped, err := s.Query()
	if err != nil {
		return err
	}
	if stopped.Win32ExitCode != 0 {
		return fmt.Errorf("service cleanup failed; run doctor/recover before update")
	}
	// Update only the description through SCM; owner, start type and recovery settings stay intact.
	config.Description = serviceDescription
	if err = s.UpdateConfig(config); err != nil {
		if wasRunning {
			_ = s.Start()
		}
		return err
	}
	err = replaceServiceExecutable(target, staged, backup, func() error {
		if !wasRunning {
			return nil
		}
		if err := s.Start(); err != nil {
			return err
		}
		return waitServiceState(s, svc.Running)
	}, func() error { return stopUpdateService(s) })
	if errors.Is(err, errUpdateRolledBack) && wasRunning {
		if restartErr := s.Start(); restartErr != nil {
			return errors.Join(err, restartErr)
		}
		if restartErr := waitServiceState(s, svc.Running); restartErr != nil {
			return errors.Join(err, restartErr)
		}
	}
	if err != nil {
		return err
	}
	fmt.Println("Service updated; owner and startup settings preserved. VPN remains disconnected.")
	return nil
}
