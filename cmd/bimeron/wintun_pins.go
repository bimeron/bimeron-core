package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Pinned SHA-256 digests of the Wintun 0.14.1 files shipped next to the
// Windows binary. Keep them in sync with scripts/check-dist.go.
var wintunDLLSHA256 = map[string]string{
	"amd64": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
	"arm64": "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
}

const wintunLicenseSHA256 = "183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2"

// copyVerifiedServiceFile copies source and verifies the copy, not the source,
// so a source replaced during installation cannot pass verification. The
// destination is removed when its digest does not match.
func copyVerifiedServiceFile(source, destination, wantSHA256 string, copyFile func(string, string) error) error {
	if err := copyFile(source, destination); err != nil {
		return err
	}
	got, err := regularFileSHA256(destination)
	if err == nil && got != wantSHA256 {
		err = fmt.Errorf("%s SHA-256 mismatch", filepath.Base(destination))
	}
	if err != nil {
		return errors.Join(err, os.Remove(destination))
	}
	return nil
}
