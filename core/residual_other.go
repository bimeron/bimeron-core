//go:build !windows && !linux

package core

func residualProtection() (bool, error) { return false, nil }
