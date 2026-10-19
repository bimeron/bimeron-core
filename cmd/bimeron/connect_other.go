//go:build !windows && !linux && !darwin

package main

import "fmt"

func connect([]string) error { return fmt.Errorf("system VPN currently requires Windows or Linux") }
func recoverVPN([]string) error {
	return fmt.Errorf("system VPN currently requires Windows or Linux")
}
