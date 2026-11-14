package winres

import (
	"debug/pe"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildWindows links a minimal windows/goarch program, with the COFF
// object when syso is non-nil, and returns the executable path.
func buildWindows(t *testing.T, goarch string, syso []byte) string {
	t.Helper()
	if testing.Short() {
		t.Skip("links Windows executables")
	}
	dir := t.TempDir()
	files := map[string][]byte{
		"go.mod":  []byte("module example.com/winrestest\n\ngo 1.26\n"),
		"main.go": []byte("package main\n\nfunc main() {}\n"),
	}
	if syso != nil {
		files["zz_resource_windows_"+goarch+".syso"] = syso
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(dir, "test.exe")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", exe, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+goarch, "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return exe
}

func TestLinkedExecutable(t *testing.T) {
	ico := sourceIcon(t)
	for arch, machine := range map[string]uint16{"amd64": pe.IMAGE_FILE_MACHINE_AMD64, "arm64": pe.IMAGE_FILE_MACHINE_ARM64} {
		t.Run(arch, func(t *testing.T) {
			obj, err := Object(arch, ico, "0.4.0-beta.1")
			if err != nil {
				t.Fatal(err)
			}
			f, err := pe.Open(buildWindows(t, arch, obj))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if f.Machine != machine {
				t.Fatalf("machine %#x, want %#x", f.Machine, machine)
			}
			if err := Verify(f, ico, "0.4.0-beta.1"); err != nil {
				t.Fatal(err)
			}
			if err := Verify(f, ico, ""); err != nil {
				t.Fatal(err)
			}
			if err := Verify(f, ico, "0.4.0"); err == nil {
				t.Fatal("accepted the wrong version")
			}
			if err := Verify(f, icoFile([]byte("other image")), ""); err == nil {
				t.Fatal("accepted a different icon")
			}

			plain, err := pe.Open(buildWindows(t, arch, nil))
			if err != nil {
				t.Fatal(err)
			}
			defer plain.Close()
			if err := Verify(plain, ico, ""); err == nil {
				t.Fatal("accepted an executable without resources")
			}
		})
	}
}
