//go:build linux

package main

import (
	"bimeron/internal/control"
	"bimeron/internal/linuxnet"
	"bimeron/internal/unixutil"
	"context"
	"debug/elf"
	"fmt"

	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type linuxRepairBackend struct {
	observedStopped bool
	release         func()
	damaged         bool
	owner           uint32
}

// owner is obtained from SO_PEERCRED by the authenticated transport.
func newLinuxRepairBackend(owner uint32) (*linuxRepairBackend, error) {
	if os.Geteuid() != 0 || owner == 0 {
		return nil, fmt.Errorf("repair identity rejected")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if err = protectedRepairPath(exe); err != nil {
		return nil, err
	}
	release, err := unixutil.Lock("repair.lock")
	if err != nil {
		return nil, err
	}
	return &linuxRepairBackend{owner: owner, release: release}, nil
}
func (b *linuxRepairBackend) Close() {
	if b.release != nil {
		b.release()
	}
}
func protectedRepairPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("repair path is not absolute")
	}
	for {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		s, ok := info.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("unprotected repair path")
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
func repairSystemctl(ctx context.Context, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	out, err := command.Output()
	return string(out), err
}
func (b *linuxRepairBackend) identity() error {
	if err := protectedRepairPath(linuxServiceUnit); err != nil {
		return err
	}
	data, err := os.ReadFile(linuxServiceUnit)
	if err != nil {
		return err
	}
	if string(data) != linuxServiceUnitText(b.owner) {
		return fmt.Errorf("service ownership unproven")
	}
	if _, err := os.Lstat(linuxServiceExecutable); os.IsNotExist(err) {
		return protectedRepairPath(linuxServiceDir)
	}
	return protectedRepairPath(linuxServiceExecutable)
}
func (b *linuxRepairBackend) Inspect(ctx context.Context) (repairObservation, error) {
	b.observedStopped = false
	b.damaged = false
	if _, err := os.Lstat(linuxServiceUnit); os.IsNotExist(err) {
		if found, e := b.inspectDeveloper(ctx); e != nil {
			return repairObservation{}, e
		} else if found {
			return repairObservation{}, fmt.Errorf("legacy developer identity unavailable; live daemon not adopted")
		}
		// Do not overwrite a leftover executable or a unit loaded from another path.
		if _, err = os.Lstat(linuxServiceExecutable); !os.IsNotExist(err) {
			return repairObservation{}, fmt.Errorf("existing service payload requires reconciliation")
		}
		state, e := repairSystemctl(ctx, "show", "--property=LoadState", "--value", linuxServiceName)
		if e != nil || strings.TrimSpace(state) != "not-found" {
			return repairObservation{}, fmt.Errorf("service absence unproven")
		}
		if err := repairLinuxConflictGate(); err != nil {
			return repairObservation{}, err
		}
		return repairObservation{Missing: true}, nil
	}
	if err := b.loadedIdentity(ctx); err != nil {
		return repairObservation{}, err
	}
	dropins, err := repairSystemctl(ctx, "show", "--property=DropInPaths", "--value", linuxServiceName)
	if err != nil || strings.TrimSpace(dropins) != "" {
		return repairObservation{}, fmt.Errorf("service overrides untrusted")
	}
	state, err := observeStableLinuxService(ctx)
	if err != nil {
		return repairObservation{}, err
	}
	switch strings.TrimSpace(state) {
	case "inactive", "failed":
		b.observedStopped = true
		image, imageErr := elf.Open(linuxServiceExecutable)
		if imageErr == nil {
			image.Close()
		} else {
			b.damaged = true
			if err := repairLinuxConflictGate(); err != nil {
				return repairObservation{}, err
			}
			journal, e := repairLinuxJournal()
			if e != nil {
				return repairObservation{}, e
			}
			mainPID, e := repairSystemctl(ctx, "show", "--property=MainPID", "--value", linuxServiceName)
			if e != nil || strings.TrimSpace(mainPID) != "0" {
				return repairObservation{}, fmt.Errorf("service exit unconfirmed")
			}
			if !journal {
				if e = b.CleanupProven(ctx); e != nil {
					code, codeErr := repairSystemctl(ctx, "show", "--property=ExecMainStatus", "--value", linuxServiceName)
					if codeErr != nil || strings.TrimSpace(code) != "203" {
						return repairObservation{}, e
					}
				}
			}
			return repairObservation{Owned: true, Stopped: true, ReplacementRequired: true, CleanupRequired: journal}, nil
		}
		if found, e := b.inspectDeveloper(ctx); e != nil {
			return repairObservation{}, e
		} else if found {
			return repairObservation{}, fmt.Errorf("legacy developer identity unavailable; live daemon not adopted")
		}
		journal, journalErr := repairLinuxJournal()
		if journalErr != nil {
			return repairObservation{}, journalErr
		}
		if journal {
			return repairObservation{Owned: true, CleanupRequired: true}, nil
		}
		if err = b.CleanupProven(ctx); err != nil {
			return repairObservation{}, err
		}
		return repairObservation{Owned: true, Stopped: true}, nil
	case "active":
		probe, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		hello, helloErr := control.CallService(probe, control.Request{Command: "hello"})
		if helloErr == nil || hello.Version != 0 {
			if err = validateRepairHello(hello); err != nil {
				return repairObservation{Owned: true, ReplacementRequired: true}, nil
			}
		}
		return repairObservation{Owned: true, Unresponsive: b.readyOnce(probe) != nil}, nil
	default:
		return repairObservation{}, fmt.Errorf("service transition or failure requires reconciliation")
	}
}
func (b *linuxRepairBackend) Install(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Lstat(linuxServiceUnit); !os.IsNotExist(err) {
		return fmt.Errorf("service appeared during repair")
	}
	if err := protectedRepairPath(filepath.Dir(linuxServiceUnit)); err != nil {
		return err
	}
	if err := repairLinuxConflictGate(); err != nil {
		return err
	}
	if err := ensureLinuxServiceDir(); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err = copyLinuxServiceFile(exe, linuxServiceExecutable); err != nil {
		return err
	}
	if err = writeLinuxServiceUnit(b.owner); err != nil {
		os.Remove(linuxServiceExecutable)
		return err
	}
	if _, err = repairSystemctl(ctx, "daemon-reload"); err != nil {
		os.Remove(linuxServiceUnit)
		os.Remove(linuxServiceExecutable)
		return err
	}
	return nil
}
func (b *linuxRepairBackend) Stop(ctx context.Context) error {
	if err := b.loadedIdentity(ctx); err != nil {
		return err
	}
	_, err := repairSystemctl(ctx, "stop", linuxServiceName)
	return err
}
func (b *linuxRepairBackend) CleanupProven(ctx context.Context) error {
	out, err := repairSystemctl(ctx, "show", "--property=Result", "--property=MainPID", "--property=ActiveState", linuxServiceName)
	if err != nil {
		return err
	}
	values := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			values[k] = v
		}
	}
	if values["Result"] != "success" || values["MainPID"] != "0" || values["ActiveState"] != "inactive" {
		return fmt.Errorf("service cleanup unconfirmed")
	}
	return nil
}
func (b *linuxRepairBackend) Recover(ctx context.Context) error {
	if err := b.loadedIdentity(ctx); err != nil {
		return err
	}
	present, err := repairLinuxJournal()
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("owned recovery journal missing")
	}
	release, err := linuxnet.Lock("vpn.lock")
	if err != nil {
		return err
	}
	defer release()
	if err = repairLinuxConflictGate(); err != nil {
		return err
	}
	if err = linuxnet.NewManager().Recover(ctx, false); err != nil {
		return err
	}
	present, err = repairLinuxJournal()
	if err != nil {
		return err
	}
	if present {
		return fmt.Errorf("network cleanup incomplete")
	}
	_, err = repairSystemctl(ctx, "reset-failed", linuxServiceName)
	return err
}
func (b *linuxRepairBackend) Start(ctx context.Context) error {
	if err := b.loadedIdentity(ctx); err != nil {
		return err
	}
	if err := repairLinuxConflictGate(); err != nil {
		return err
	}
	_, err := repairSystemctl(ctx, "start", linuxServiceName)
	return err
}
func (b *linuxRepairBackend) readyOnce(ctx context.Context) error {
	return verifyServiceReadiness(ctx, control.CallService, validateRepairHello)
}
func (b *linuxRepairBackend) Rollback(ctx context.Context) error {
	if err := b.Stop(ctx); err != nil {
		return err
	}
	if err := b.CleanupProven(ctx); err != nil {
		return err
	}
	if err := os.Remove(linuxServiceUnit); err != nil {
		return err
	}
	if err := os.Remove(linuxServiceExecutable); err != nil {
		return err
	}
	_, err := repairSystemctl(ctx, "daemon-reload")
	return err
}

func newRepairBackend(identity string) (repairBackend, error) {
	var uid uint32
	if _, err := fmt.Sscanf(identity, "%d", &uid); err != nil {
		return nil, err
	}
	return newLinuxRepairBackend(uid)
}

func (b *linuxRepairBackend) Ready(ctx context.Context) error {
	return waitRepairReady(ctx, b.readyOnce)
}

func (b *linuxRepairBackend) Replace(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.loadedIdentity(ctx); err != nil {
		return err
	}
	if b.observedStopped {
		state, err := repairSystemctl(ctx, "show", "--property=ActiveState", "--value", linuxServiceName)
		if err != nil {
			return err
		}
		if strings.TrimSpace(state) != "inactive" && strings.TrimSpace(state) != "failed" {
			return fmt.Errorf("service state changed before replacement")
		}
	}
	source, err := protectedSelfUpdate()
	if err != nil {
		return err
	}
	if b.damaged {
		return repairDamagedPayload(ctx, linuxServiceExecutable, copyLinuxServiceFile, func(ctx context.Context) error {
			if err := b.Start(ctx); err != nil {
				return err
			}
			return b.Ready(ctx)
		}, func(ctx context.Context) error {
			if err := b.Stop(ctx); err != nil {
				return err
			}
			return b.CleanupProven(ctx)
		})
	}
	return updateLinuxServiceMode(ctx, source, true)
}

func (b *linuxRepairBackend) loadedIdentity(ctx context.Context) error {
	if err := b.identity(); err != nil {
		return err
	}
	out, err := repairSystemctl(ctx, "show", "--property=FragmentPath", "--property=DropInPaths", "--property=User", "--property=ExecStart", linuxServiceName)
	if err != nil {
		return err
	}
	values := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			values[k] = v
		}
	}
	if values["FragmentPath"] != linuxServiceUnit || values["DropInPaths"] != "" || (values["User"] != "" && values["User"] != "root") || !strings.Contains(values["ExecStart"], "path="+linuxServiceExecutable+" ; argv[]="+linuxServiceExecutable+" daemon ;") {
		return fmt.Errorf("loaded service identity unproven")
	}
	return nil
}

func repairLinuxConflictGate() error {
	release, err := unixutil.Lock("daemon.lock")
	if err != nil {
		return err
	}
	defer release()
	if _, err = os.Lstat(filepath.Join(unixutil.RuntimeDir, "control.sock")); !os.IsNotExist(err) {
		return fmt.Errorf("control endpoint absence unproven")
	}
	return nil
}

func repairLinuxJournal() (bool, error) {
	path := filepath.Join(unixutil.RuntimeDir, "state.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return false, nil
	}
	if err := protectedRepairPath(path); err != nil {
		return false, err
	}
	state, err := linuxnet.NewManager().Load()
	if err != nil {
		return false, err
	}
	return state != nil, nil
}

func observeStableLinuxService(ctx context.Context) (state string, err error) {
	err = observeRepairTransition(ctx, func(ctx context.Context) (bool, error) {
		var e error
		state, e = repairSystemctl(ctx, "show", "--property=ActiveState", "--value", linuxServiceName)
		if e != nil {
			return false, e
		}
		switch strings.TrimSpace(state) {
		case "activating", "deactivating", "reloading":
			return false, nil
		}
		return true, nil
	})
	return
}
