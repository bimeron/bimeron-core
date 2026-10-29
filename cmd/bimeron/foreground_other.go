//go:build !windows

package main

import "errors"

func foregroundCommand([]string) error { return errors.New("ikev2_platform_unsupported") }

func profileControlCommand([]string) error { return errors.New("ikev2_platform_unsupported") }
