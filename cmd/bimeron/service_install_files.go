package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// serviceInstallFiles are the files service install places in the protected
// installation directory.
var serviceInstallFiles = []string{"bimeron.exe", "wintun.dll", "WINTUN-LICENSE.txt"}

// updateHoldFile is the record of kill switch protection kept across a
// service update (ADR 0041), in the protected installation directory. The
// service writes it; uninstall removes it with the installed files.
const updateHoldFile = "kill-switch-update-hold.json"

// serviceRecordFiles are files the running service may leave in the
// installation directory.
var serviceRecordFiles = []string{updateHoldFile, updateHoldFile + ".new"}

// removeServiceFiles deletes installed service files from dir. Missing files
// are tolerated so an interrupted uninstall can be resumed. Only regular files
// are removed; links and other objects are reported instead of followed.
func removeServiceFiles(dir string) error {
	var errs []error
	for _, name := range append(append([]string(nil), serviceInstallFiles...), serviceRecordFiles...) {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !info.Mode().IsRegular() {
			errs = append(errs, fmt.Errorf("%s is not a regular file", path))
			continue
		}
		if err = os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// uninstallServiceArtifacts deletes the service registration first, when one
// exists, and keeps the files if that fails so a registered service never loses
// its executable. The event source and files are then removed independently:
// already-removed artifacts are tolerated and every failure is reported, so a
// repeated uninstall resumes an interrupted one.
func uninstallServiceArtifacts(deleteService, removeEventSource, removeFiles func() error) error {
	if deleteService != nil {
		if err := deleteService(); err != nil {
			return err
		}
	}
	var errs []error
	if err := removeEventSource(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove event log source: %w", err))
	}
	if err := removeFiles(); err != nil {
		errs = append(errs, fmt.Errorf("remove service files: %w", err))
	}
	return errors.Join(errs...)
}
