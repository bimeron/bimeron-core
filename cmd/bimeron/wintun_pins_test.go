package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWintunPinsMatchDistributionCheck(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "check-dist.go"))
	if err != nil {
		t.Fatal(err)
	}
	for arch, digest := range wintunDLLSHA256 {
		if !strings.Contains(string(script), `"`+arch+`": "`+digest+`"`) {
			t.Fatalf("Wintun %s digest differs from scripts/check-dist.go", arch)
		}
	}
	if !strings.Contains(string(script), `"WINTUN-LICENSE.txt": "`+wintunLicenseSHA256+`"`) {
		t.Fatal("Wintun license digest differs from scripts/check-dist.go")
	}
}

func TestCopyVerifiedServiceFileChecksTheCopy(t *testing.T) {
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "source.dll"), filepath.Join(dir, "wintun.dll")
	if err := os.WriteFile(source, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	copyFile := func(from, to string) error {
		data, err := os.ReadFile(from)
		if err != nil {
			return err
		}
		return os.WriteFile(to, data, 0600)
	}
	err := copyVerifiedServiceFile(source, destination, wintunDLLSHA256["amd64"], copyFile)
	if err == nil || err.Error() != "wintun.dll SHA-256 mismatch" {
		t.Fatal("unpinned Wintun DLL not reported as a digest mismatch:", err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("mismatched copy kept:", err)
	}
	const tamperedSHA256 = "d121be3103007b41edf96f8262925f8c7d61894afe9a041843b631f69445bc57"
	if err := copyVerifiedServiceFile(source, destination, tamperedSHA256, copyFile); err != nil {
		t.Fatal("matching copy rejected:", err)
	}
}
