package main

import "fmt"

// serviceStateNames names the Windows SCM service states. The Linux service
// maps systemd states onto the same codes.
var serviceStateNames = map[uint32]string{
	1: "stopped",
	2: "start_pending",
	3: "stop_pending",
	4: "running",
	5: "continue_pending",
	6: "pause_pending",
	7: "paused",
}

// formatServiceState keeps the numeric code first for existing parsers and
// appends a readable name.
func formatServiceState(code uint32) string {
	name, ok := serviceStateNames[code]
	if !ok {
		name = "unknown"
	}
	return fmt.Sprintf("%d (%s)", code, name)
}
