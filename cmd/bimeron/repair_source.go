package main

import (
	"bimeron/core"
	"bimeron/internal/control"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// protectedSelfUpdate binds the source digest to the broker's protected image,
// not a caller-selected file or caller-supplied digest.
func protectedSelfUpdate() (updateExpectation, error) {
	exe, err := os.Executable()
	if err != nil {
		return updateExpectation{}, err
	}
	f, err := os.Open(exe)
	if err != nil {
		return updateExpectation{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return updateExpectation{}, err
	}
	return updateExpectation{source: exe, version: core.GetBuildInfo().Version, sha256: hex.EncodeToString(h.Sum(nil))}, nil
}

func repairDamagedPayload(ctx context.Context, target string, copyFile func(string, string) error, activate func(context.Context) error, deactivate func(context.Context) error) error {
	source, err := protectedSelfUpdate()
	if err != nil {
		return err
	}
	staged := target + ".repair-new"
	backup := target + ".repair-old"
	if _, err = os.Lstat(staged); !os.IsNotExist(err) {
		return fmt.Errorf("previous repair candidate requires reconciliation")
	}
	if _, err = os.Lstat(backup); !os.IsNotExist(err) {
		return fmt.Errorf("previous repair backup requires reconciliation")
	}
	if err = stageVerifiedUpdate(source.source, staged, source.sha256, copyFile); err != nil {
		return err
	}
	defer os.Remove(staged)
	rollback, done := updateRollbackContext(ctx)
	defer done()
	if _, err = os.Lstat(target); os.IsNotExist(err) {
		if err = os.Rename(staged, target); err != nil {
			return err
		}
		if err = activate(ctx); err != nil {
			if stopErr := deactivate(rollback()); stopErr != nil {
				return errors.Join(err, stopErr)
			}
			return errors.Join(err, os.Remove(target))
		}
		return nil
	}
	return replaceServiceExecutable(target, staged, backup, func() error { return activate(ctx) }, func() error { return deactivate(rollback()) })
}

// Repair preserves a healthy service across Core release versions. The Desktop
// protocol contract is negotiated by IPC version, not broker semantic version.
func validateRepairHello(a control.Response) error {
	if a.Error != "" || a.Version != control.Version || a.Core == nil || a.Core.Version == "" || a.Instance == "" {
		return fmt.Errorf("incompatible service hello")
	}
	return nil
}

func validateRepairStatus(a control.Response, instance string) error {
	if instance == "" || a.Error != "" || a.Version != control.Version || a.Instance != instance {
		return fmt.Errorf("service status not ready")
	}
	switch a.Status.State {
	case core.Disconnected, core.Connected, core.Connecting, core.Reconnecting:
		return nil
	}
	return fmt.Errorf("service status not ready")
}

func verifyServiceReadiness(ctx context.Context, call func(context.Context, control.Request) (control.Response, error), validateHello func(control.Response) error) error {
	hello, err := call(ctx, control.Request{Command: "hello"})
	if err != nil {
		return err
	}
	if err = validateHello(hello); err != nil {
		return err
	}
	// Instance is a foreground-only request field. Standard services return their
	// instance in every response; bind the two responses without sending it.
	status, err := call(ctx, control.Request{Command: "status"})
	if err != nil {
		return err
	}
	return validateRepairStatus(status, hello.Instance)
}
