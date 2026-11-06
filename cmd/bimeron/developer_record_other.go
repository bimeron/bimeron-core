//go:build !linux && !windows

package main

func beginDeveloperRecord() (func(bool) error, error) { return func(bool) error { return nil }, nil }
