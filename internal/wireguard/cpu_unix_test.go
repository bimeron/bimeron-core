//go:build linux || darwin

package wireguard

import (
	"syscall"
	"time"
)

// processCPU returns user plus system CPU time of this process.
func processCPU() time.Duration {
	var u syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &u) != nil {
		return 0
	}
	return time.Duration(u.Utime.Nano() + u.Stime.Nano())
}
