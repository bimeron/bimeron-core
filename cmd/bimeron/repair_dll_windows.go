//go:build windows

package main

import (
	"bimeron/internal/control"
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func repairDLLDamaged(path string) bool {
	f, err := pe.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()
	exe, err := os.Executable()
	if err != nil {
		return true
	}
	self, err := pe.Open(exe)
	if err != nil {
		return true
	}
	defer self.Close()
	return f.Machine != self.Machine || f.Characteristics&0x2000 == 0
}
func stageRepairDLL(ctx context.Context, target string) (func(bool) error, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	source := filepath.Join(filepath.Dir(exe), "wintun.dll")
	unlock, err := control.LockRepairImage(source)
	if err != nil || repairDLLDamaged(source) {
		if unlock != nil {
			unlock()
		}
		data, downloadErr := acquireRepairMember(ctx, "wintun.dll")
		if downloadErr != nil {
			return nil, fmt.Errorf("protected Wintun source unavailable; signed acquisition: %w", downloadErr)
		}
		source, err = stageRepairDownload(target, data)
		if err != nil {
			return nil, err
		}
		defer os.Remove(source)
		unlock, err = control.LockRepairImage(source)
		if err != nil {
			return nil, err
		}
	}
	defer unlock()
	if repairDLLDamaged(source) {
		return nil, fmt.Errorf("authenticated Wintun architecture invalid")
	}
	f, err := os.Open(source)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil {
		return nil, err
	}
	staged, backup := target+".repair-new", target+".repair-old"
	for _, p := range []string{staged, backup} {
		if _, err = os.Lstat(p); !os.IsNotExist(err) {
			return nil, fmt.Errorf("previous Wintun repair requires reconciliation")
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = stageVerifiedUpdate(source, staged, hex.EncodeToString(h.Sum(nil)), copyServiceFile); err != nil {
		return nil, err
	}
	defer os.Remove(staged)
	hadOriginal := false
	if _, err = os.Lstat(target); err == nil {
		if err = os.Rename(target, backup); err != nil {
			return nil, err
		}
		hadOriginal = true
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err = os.Rename(staged, target); err != nil {
		if hadOriginal {
			return nil, errors.Join(err, os.Rename(backup, target))
		}
		return nil, err
	}
	return func(success bool) error {
		if success {
			if hadOriginal {
				return os.Remove(backup)
			}
			return nil
		}
		if err := os.Remove(target); err != nil {
			return err
		}
		if hadOriginal {
			return os.Rename(backup, target)
		}
		return nil
	}, nil
}
