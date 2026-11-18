//go:build !windows

package safefile

import "os"

func regular(m os.FileMode) bool { return m.IsRegular() }

func checkOpened(*os.File) error { return nil }
