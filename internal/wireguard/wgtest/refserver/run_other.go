//go:build !linux

package main

import "errors"

func run(string, string, string) error {
	return errors.New("refserver requires Linux")
}
