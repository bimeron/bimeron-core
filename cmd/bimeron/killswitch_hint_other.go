//go:build !windows

package main

func killSwitchHint(err error) error { return err }
