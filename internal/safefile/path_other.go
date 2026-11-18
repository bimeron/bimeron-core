//go:build !windows

package safefile

func local(string) bool { return true }
