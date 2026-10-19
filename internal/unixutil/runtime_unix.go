//go:build linux || darwin

// Package unixutil owns root-only runtime files and advisory process locks.
package unixutil

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

func EnsureRuntimeDir() error {
	return EnsureRootDir(RuntimeDir, 0711)
}
func EnsureRootDir(path string, mode os.FileMode) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root required; use sudo")
	}
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("unsafe Bimeron runtime directory")
	}
	if info.Mode().Perm() != mode {
		return os.Chmod(path, mode)
	}
	return nil
}
func Lock(name string) (func(), error) {
	if filepath.Base(name) != name {
		return nil, fmt.Errorf("invalid lock name")
	}
	if err := EnsureRuntimeDir(); err != nil {
		return nil, err
	}
	return LockFile(filepath.Join(RuntimeDir, name))
}

// Lock files are not unlinked, so another process cannot lock a different inode.
func LockFile(path string) (func(), error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("another Bimeron owner is active")
	}
	var once sync.Once
	return func() { once.Do(func() { unix.Flock(fd, unix.LOCK_UN); unix.Close(fd) }) }, nil
}
