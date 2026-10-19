//go:build !windows && !linux && !darwin

package main

import "fmt"

func daemon([]string) error { return fmt.Errorf("daemon currently requires Windows or Linux") }
