//go:build !linux && !darwin

package wireguard

import "time"

// processCPU is not measured on this platform.
func processCPU() time.Duration { return 0 }
