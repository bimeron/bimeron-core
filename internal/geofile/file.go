// Package geofile opens local regular dataset files without waiting for Unix FIFOs.
package geofile

import (
	"fmt"
	"os"
)

func Open(path string) (*os.File, error) {
	f, err := open(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("dataset must be a regular file")
	}
	return f, nil
}
