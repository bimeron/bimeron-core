//go:build !windows

package releasecard

import "errors"

type pcscContext struct{}

type pcscCard struct{}

func openContext() (*pcscContext, error) {
	return nil, errors.New("release card signing is supported only on Windows")
}

func (*pcscContext) Close() error                      { return nil }
func (*pcscContext) Readers() ([]string, error)        { return nil, errNoReaders }
func (*pcscContext) Connect(string) (*pcscCard, error) { return nil, errNoReaders }
func (*pcscCard) Close() error                         { return nil }
func (*pcscCard) Transmit([]byte) ([]byte, error)      { return nil, errNoReaders }
