//go:build !windows

package core

import "os"

func writeHoldFile(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }

func installedFilterGeneration() (string, error) { return "", os.ErrInvalid }
