//go:build linux

package main

import (
	"bimeron/internal/unixutil"
	"context"
	"os"
	"path/filepath"
)

func (b *linuxRepairBackend) inspectDeveloper(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, err := os.Lstat(filepath.Join(unixutil.RuntimeDir, "control.sock"))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
