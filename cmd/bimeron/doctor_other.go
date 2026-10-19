//go:build !windows && !darwin

package main

import "context"

func hostDiagnostics(context.Context) []diagnosticCheck {
	return []diagnosticCheck{{Name: "system_network_inspection", Result: "not_implemented_on_this_platform"}}
}
