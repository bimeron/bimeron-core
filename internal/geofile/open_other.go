//go:build !linux && !darwin && !android

package geofile

import "os"

func open(path string) (*os.File, error) { return os.Open(path) }
