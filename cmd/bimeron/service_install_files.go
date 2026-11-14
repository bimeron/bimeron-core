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

// removeServiceFiles deletes installed service files from dir. Missing files
// are tolerated so an interrupted uninstall can be resumed. Only regular files
// are removed; links and other objects are reported instead of followed.
func removeServiceFiles(dir string) error {
	var errs []error
	for _, name := range serviceInstallFiles {
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
