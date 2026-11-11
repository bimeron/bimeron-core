//go:build windows

package main

import (
	"bimeron/internal/control"
	"bimeron/internal/killswitch"
	"bimeron/internal/windowsnet"
	"context"
	"crypto/sha256"
	"debug/pe"

	"errors"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type windowsRepairBackend struct {
	observedStopped bool
	dllDamaged      bool
	damaged         bool
	owner           string
	manager         *mgr.Mgr
	service         *mgr.Service
	unlock          func()
	imageUnlock     func()
	recovered       bool
	session         uint32
}

// callerSID must come from the authenticated transport, never request JSON.
func newWindowsRepairBackend(callerSID string) (*windowsRepairBackend, error) {
	if !windowsnet.Elevated() {
		return nil, fmt.Errorf("repair requires elevation")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	unlock, err := control.LockRepairImage(exe)
	if err != nil {
		return nil, err
	}
	m, err := mgr.Connect()
	if err != nil {
		unlock()
		return nil, err
	}
	release, err := windowsnet.BeginRepairTransaction()
	if err != nil {
		m.Disconnect()
		unlock()
		return nil, err
	}
	return &windowsRepairBackend{owner: callerSID, manager: m, unlock: func() { release(); unlock() }}, nil
}
func (b *windowsRepairBackend) Close() {
	if b.service != nil {
		b.service.Close()
	}
	if b.imageUnlock != nil {
		b.imageUnlock()
		b.imageUnlock = nil
	}
	b.manager.Disconnect()
	b.unlock()
}
func (b *windowsRepairBackend) Inspect(ctx context.Context) (repairObservation, error) {
	if b.service != nil {
		b.service.Close()
		b.service = nil
	}
	if b.imageUnlock != nil {
		b.imageUnlock()
		b.imageUnlock = nil
	}
	b.recovered = false
	b.observedStopped = false
	b.damaged = false
	b.dllDamaged = false
	if err := ctx.Err(); err != nil {
		return repairObservation{}, err
	}
	s, err := b.manager.OpenService(serviceName)
	if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		if found, e := b.inspectDeveloper(ctx); e != nil {
			return repairObservation{}, e
		} else if found {
			return repairObservation{}, fmt.Errorf("legacy developer identity unavailable; live daemon not adopted")
		}
		if err := repairWindowsConflictGate(ctx, b.owner); err != nil {
			return repairObservation{}, err
		}
		return repairObservation{Missing: true}, nil
	}
	if err != nil {
		return repairObservation{}, err
	}
	b.service = s
	config, err := s.Config()
	if err != nil {
		return repairObservation{}, err
	}
	argv, err := windows.DecomposeCommandLine(config.BinaryPathName)
	root, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil || e != nil || len(argv) != 4 || argv[1] != "service" || argv[2] != "run" || argv[3] != b.owner || !strings.EqualFold(filepath.Clean(argv[0]), filepath.Join(root, "Bimeron Core", "bimeron.exe")) || config.ServiceStartName != "LocalSystem" {
		return repairObservation{}, fmt.Errorf("service ownership unproven")
	}
	b.dllDamaged = repairDLLDamaged(filepath.Join(filepath.Dir(argv[0]), "wintun.dll"))
	statusBefore, err := observeStableWindowsService(ctx, s)
	if err != nil {
		return repairObservation{}, err
	}
	b.observedStopped = statusBefore.State == svc.Stopped
	if statusBefore.State == svc.Stopped {
		image, imageErr := pe.Open(argv[0])
		if imageErr == nil {
			image.Close()
		} else {
			b.damaged = true
			unlock, e := control.LockRepairDirectory(filepath.Dir(argv[0]))
			if e != nil {
				return repairObservation{}, e
			}
			b.imageUnlock = unlock
			if err := repairWindowsConflictGate(ctx, b.owner); err != nil {
				return repairObservation{}, err
			}
			if statusBefore.ProcessId != 0 {
				return repairObservation{}, fmt.Errorf("service exit unconfirmed")
			}
			pending, e := repairWindowsCleanupPending(ctx)
			if e != nil {
				return repairObservation{}, e
			}
			if !pending && !windowsServiceExitClean(statusBefore) && statusBefore.Win32ExitCode != uint32(windows.ERROR_FILE_NOT_FOUND) && statusBefore.Win32ExitCode != 193 {
				return repairObservation{}, fmt.Errorf("service cleanup unconfirmed")
			}
			return repairObservation{Owned: true, Stopped: true, ReplacementRequired: true, CleanupRequired: pending}, nil
		}
	}
	unlock, err := control.LockRepairImage(argv[0])
	if err != nil {
		return repairObservation{}, err
	}
	b.imageUnlock = unlock

	status, err := s.Query()
	if err != nil {
		return repairObservation{}, err
	}
	if status.State == svc.Stopped {
		if found, e := b.inspectDeveloper(ctx); e != nil {
			return repairObservation{}, e
		} else if found {
			return repairObservation{}, fmt.Errorf("legacy developer identity unavailable; live daemon not adopted")
		}
		pending, pendingErr := repairWindowsCleanupPending(ctx)
		if pendingErr != nil {
			return repairObservation{}, pendingErr
		}
		if pending {
			return repairObservation{Owned: true, CleanupRequired: true}, nil
		}
		if !windowsServiceExitClean(status) {
			return repairObservation{}, fmt.Errorf("previous service cleanup unconfirmed")
		}
		return repairObservation{Owned: true, Stopped: true, ReplacementRequired: b.dllDamaged}, nil
	}
	if status.State != svc.Running {
		return repairObservation{}, fmt.Errorf("service transition in progress")
	}
	if b.dllDamaged {
		return repairObservation{Owned: true, ReplacementRequired: true}, nil
	}
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	hello, helloErr := control.CallService(probe, control.Request{Command: "hello"})
	if helloErr == nil || hello.Version != 0 {
		if err = validateRepairHello(hello); err != nil {
			return repairObservation{Owned: true, ReplacementRequired: true}, nil
		}
	}
	err = b.readyOnce(probe)
	return repairObservation{Owned: true, Unresponsive: err != nil}, nil
}
func (b *windowsRepairBackend) Install(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := repairWindowsConflictGate(ctx, b.owner); err != nil {
		return err
	}
	return serviceCommandForOwner([]string{"install"}, b.owner)
}
func (b *windowsRepairBackend) Stop(ctx context.Context) error {
	if b.service == nil {
		return fmt.Errorf("service identity unavailable")
	}
	if err := b.validateIdentity(); err != nil {
		return err
	}
	before, err := b.service.Query()
	if err != nil {
		return err
	}
	if before.ProcessId == 0 {
		return fmt.Errorf("service process identity unavailable")
	}
	process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, before.ProcessId)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	if _, err := b.service.Control(svc.Stop); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		status, err := b.service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {

			result, err := windows.WaitForSingleObject(process, 0)
			if err != nil || result != windows.WAIT_OBJECT_0 {
				return fmt.Errorf("service process has not exited")
			}
			return b.CleanupProven(ctx)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (b *windowsRepairBackend) CleanupProven(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.service == nil {
		return fmt.Errorf("service identity unavailable")
	}
	s, err := b.service.Query()
	if err != nil {
		return err
	}
	if s.State != svc.Stopped || s.ProcessId != 0 || (!b.recovered && !windowsServiceExitClean(s)) {
		return fmt.Errorf("service exit and cleanup unconfirmed")
	}
	return nil
}
func (b *windowsRepairBackend) Recover(ctx context.Context) error {
	if err := b.validateIdentity(); err != nil {
		return err
	}
	s, err := b.service.Query()
	if err != nil {
		return err
	}
	if s.State != svc.Stopped || s.ProcessId != 0 {
		return fmt.Errorf("service exit unconfirmed")
	}
	if err := repairWindowsConflictGate(ctx, b.owner); err != nil {
		return err
	}
	release, err := windowsnet.Acquire()
	if err != nil {
		return err
	}
	defer release()
	if err = windowsnet.Recover(ctx); err != nil {
		return err
	}
	if err = windowsnet.RecoverIKEv2DNS(ctx); err != nil {
		return err
	}
	if err = killswitch.Recover(); err != nil {
		return err
	}
	pending, err := repairWindowsCleanupPending(ctx)
	if err != nil {
		return err
	}
	if pending {
		return fmt.Errorf("owned network cleanup incomplete")
	}
	b.recovered = true
	return nil
}
func (b *windowsRepairBackend) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.service == nil {
		s, err := b.manager.OpenService(serviceName)
		if err != nil {
			return err
		}
		b.service = s
	}
	if err := b.validateIdentity(); err != nil {
		return err
	}
	if err := repairWindowsConflictGate(ctx, b.owner); err != nil {
		return err
	}
	return b.service.Start()
}
func (b *windowsRepairBackend) readyOnce(ctx context.Context) error {
	return verifyServiceReadiness(ctx, control.CallService, validateRepairHello)
}
func (b *windowsRepairBackend) Rollback(ctx context.Context) error {
	if b.service == nil {
		s, err := b.manager.OpenService(serviceName)
		if err != nil {
			return err
		}
		b.service = s
	}
	s, err := b.service.Query()
	if err != nil {
		return err
	}
	if s.State != svc.Stopped {
		if err = b.Stop(ctx); err != nil {
			return err
		}
	}
	return serviceCommand([]string{"uninstall"})
}

func newRepairBackend(identity string) (repairBackend, error) {
	parts := strings.Split(identity, "|")
	if len(parts) != 2 {
		return nil, fmt.Errorf("caller session unavailable")
	}
	session, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, err
	}
	b, err := newWindowsRepairBackend(parts[0])
	if err != nil {
		return nil, err
	}
	b.session = uint32(session)
	return b, nil
}

func (b *windowsRepairBackend) validateIdentity() error {
	config, err := b.service.Config()
	if err != nil {
		return err
	}
	argv, err := windows.DecomposeCommandLine(config.BinaryPathName)
	root, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil || e != nil || len(argv) != 4 || argv[1] != "service" || argv[2] != "run" || argv[3] != b.owner || !strings.EqualFold(filepath.Clean(argv[0]), filepath.Join(root, "Bimeron Core", "bimeron.exe")) || config.ServiceStartName != "LocalSystem" {
		return fmt.Errorf("service identity changed")
	}
	return nil
}

func (b *windowsRepairBackend) Ready(ctx context.Context) error {
	return waitRepairReady(ctx, b.readyOnce)
}

func (b *windowsRepairBackend) Replace(ctx context.Context) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.validateIdentity(); err != nil {
		return err
	}
	current, err := b.service.Query()
	if err != nil {
		return err
	}
	if b.observedStopped && current.State != svc.Stopped {
		return fmt.Errorf("service state changed before replacement")
	}
	source, err := protectedSelfUpdate()
	if err != nil {
		return err
	}
	if b.imageUnlock != nil {
		b.imageUnlock()
		b.imageUnlock = nil
	}
	if b.dllDamaged {
		status, err := b.service.Query()
		if err != nil {
			return err
		}
		if status.State != svc.Stopped {
			if err = b.Stop(ctx); err != nil {
				return err
			}
		}
		root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
		if err != nil {
			return err
		}
		finalize, err := stageRepairDLL(ctx, filepath.Join(root, "Bimeron Core", "wintun.dll"))
		if err != nil {
			return err
		}
		defer func() {
			result = finishRepairSidecar(result, finalize, func() error {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				defer cancel()
				state, err := b.service.Query()
				if err != nil {
					return err
				}
				if state.State != svc.Stopped {
					return b.Stop(cleanup)
				}
				return nil
			})
		}()
	}
	if b.damaged {
		root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
		if err != nil {
			return err
		}
		return repairDamagedPayload(ctx, filepath.Join(root, "Bimeron Core", "bimeron.exe"), copyServiceFile, func(ctx context.Context) error {
			if err := b.Start(ctx); err != nil {
				return err
			}
			return b.Ready(ctx)
		}, func(ctx context.Context) error {
			s, err := b.service.Query()
			if err != nil {
				return err
			}
			if s.State == svc.Stopped {
				return nil
			}
			return b.Stop(ctx)
		})
	}
	return updateWindowsServiceMode(ctx, b.service, source, true)
}

func repairWindowsConflictGate(ctx context.Context, owner string) error {
	release, err := windowsnet.BeginInstallationTransaction()
	if err != nil {
		return err
	}
	defer release()
	probe, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	digest := sha256.Sum256([]byte(owner))
	connection, err := winio.DialPipeContext(probe, fmt.Sprintf(`\\.\pipe\Bimeron.Core.%x`, digest[:16]))
	if err == nil {
		connection.Close()
		return fmt.Errorf("caller control endpoint blocks repair")
	}
	if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return fmt.Errorf("caller endpoint absence unproven: %w", err)
	}
	connection, err = control.DialService(probe)
	if err == nil {
		connection.Close()
		return fmt.Errorf("existing control endpoint blocks repair")
	}
	if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return fmt.Errorf("control endpoint absence unproven: %w", err)
	}
	return nil
}

// windowsServiceExitClean reports whether a stopped service status proves that
// the last service process, if any, exited cleanly. ERROR_SERVICE_NEVER_STARTED
// means no service process has run since boot, so this boot left no runtime
// state behind; persistent leftovers are detected by repairWindowsCleanupPending.
func windowsServiceExitClean(s svc.Status) bool {
	if s.Win32ExitCode == uint32(windows.ERROR_SERVICE_NEVER_STARTED) {
		return s.ServiceSpecificExitCode == 0
	}
	return s.Win32ExitCode == 0 && s.ServiceSpecificExitCode == 0
}

func repairWindowsCleanupPending(ctx context.Context) (bool, error) {
	pending, err := killswitch.Pending()
	if err != nil {
		return false, err
	}
	dns, err := windowsnet.RecoveryPending(ctx)
	return pending || dns, err
}

func (b *windowsRepairBackend) inspectDeveloper(ctx context.Context) (bool, error) {
	digest := sha256.Sum256([]byte(b.owner))
	probe, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	c, err := winio.DialPipeContext(probe, fmt.Sprintf(`\\.\pipe\Bimeron.Core.%x`, digest[:16]))
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	c.Close()
	return true, nil
}

func observeStableWindowsService(ctx context.Context, s *mgr.Service) (status svc.Status, err error) {
	err = observeRepairTransition(ctx, func(context.Context) (bool, error) {
		var e error
		status, e = s.Query()
		if e != nil {
			return false, e
		}
		switch status.State {
		case svc.StartPending, svc.StopPending, svc.ContinuePending, svc.PausePending:
			return false, nil
		}
		return true, nil
	})
	return
}
