package main

import (
	"errors"
	"fmt"
	"os"
)

var errUpdateRolledBack = errors.New("previous executable restored")

func restorePreviousService(err error, wasRunning bool, restart func() error) error {
	if errors.Is(err, errUpdateRolledBack) && wasRunning {
		if restartErr := restart(); restartErr != nil {
			return errors.Join(err, restartErr)
		}
	}
	return err
}

// All paths are checked by the Windows caller and remain in the protected install directory.
// Keep the backup if restoration fails; never silently delete the last working executable.
func replaceServiceExecutable(target, staged, backup string, activate, deactivate func() error) error {
	if _, err := os.Lstat(backup); !os.IsNotExist(err) {
		return fmt.Errorf("previous update backup exists or cannot be inspected")
	}
	if err := os.Rename(target, backup); err != nil {
		return errors.Join(err, errUpdateRolledBack)
	}
	if err := os.Rename(staged, target); err != nil {
		if restoreErr := os.Rename(backup, target); restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		return errors.Join(err, errUpdateRolledBack)
	}
	if err := activate(); err != nil {
		if stopErr := deactivate(); stopErr != nil {
			return errors.Join(err, fmt.Errorf("rollback blocked; backup retained: %w", stopErr))
		}
		if removeErr := os.Remove(target); removeErr != nil {
			return errors.Join(err, removeErr)
		}
		if restoreErr := os.Rename(backup, target); restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		return errors.Join(err, errUpdateRolledBack)
	}
	if err := os.Remove(backup); err != nil {
		return fmt.Errorf("updated successfully but backup cleanup failed: %w", err)
	}
	return nil
}
