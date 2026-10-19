//go:build !windows && !linux

package main

import "fmt"

func serviceCommand([]string) error { return fmt.Errorf("service commands require Windows or Linux") }
