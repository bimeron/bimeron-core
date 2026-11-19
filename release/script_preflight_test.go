package release_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Exercise the public scripts with an isolated checkout and toolchain.
func TestReleaseScriptPreflight(t *testing.T) {
	root := t.TempDir()
	scripts := filepath.Join(root, "scripts")
	if err := os.Mkdir(scripts, 0755); err != nil {
		t.Fatal(err)
	}
	windows := runtime.GOOS == "windows"
	entries := []string{"build-all.sh", "build-android.sh", "publish-prepared-release.sh"}
	helper := "release-go.sh"
	goStub := "#!/bin/sh\nif [ \"$*\" != 'env GOFLAGS GOEXPERIMENT' ]; then touch \"$MARKER\"; exit 0; fi\nprintf '%s' \"$SETTINGS\"\nexit \"$ENV_STATUS\"\n"
	goName, mobileName := "go", "gomobile"
	if windows {
		entries = []string{"build-all.ps1", "build-android.ps1", "install-wintun.ps1"}
		helper = "release-go.ps1"
		goName, mobileName = "go.cmd", "gomobile.cmd"
		goStub = "@echo off\r\nif not \"%*\"==\"env GOFLAGS GOEXPERIMENT\" (type nul > \"%MARKER%\" & exit /b 0)\r\nif defined SETTINGS echo %SETTINGS%\r\nexit /b %ENV_STATUS%\r\n"
	}
	for _, name := range append([]string{helper}, entries...) {
		data, err := os.ReadFile(filepath.Join("..", "scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(scripts, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{goName, mobileName} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(goStub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("MARKER", filepath.Join(root, "tool-ran"))
	t.Setenv("ANDROID_HOME", root)
	t.Setenv("ANDROID_NDK_HOME", root)
	t.Setenv("BIMERON_RELEASE_TEST_UNPINNED_KEY", "")
	for _, name := range entries {
		for _, tc := range []struct{ value, status, want string }{
			{"", "9", "could not read go release settings"},
			{"-n", "0", "unset goflags and goexperiment"},
		} {
			t.Run(name+"/"+tc.status, func(t *testing.T) {
				t.Setenv("SETTINGS", tc.value)
				t.Setenv("ENV_STATUS", tc.status)
				shell := "sh"
				args := []string{filepath.Join(scripts, name)}
				if strings.HasPrefix(name, "publish-") {
					shell = "bash"
				}
				if windows {
					shell = "powershell.exe"
					args = append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File"}, args...)
				}
				cmd := exec.Command(shell, args...)
				cmd.Dir = root
				out, err := cmd.CombinedOutput()
				if err == nil || !strings.Contains(strings.ToLower(string(out)), tc.want) {
					t.Fatalf("exit %v: %s", err, out)
				}
				if _, err := os.Stat(os.Getenv("MARKER")); !os.IsNotExist(err) {
					t.Fatalf("tool invoked after preflight: %v", err)
				}
			})
		}
	}
	if windows {
		t.Setenv("SETTINGS", "")
		t.Setenv("ENV_STATUS", "0")
		cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", `
$ErrorActionPreference = 'Stop'
$dist = New-Item -ItemType Directory -Force dist
$held = [IO.File]::Open((Join-Path $dist.FullName '.android-build.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
try {
    try { ./scripts/build-android.ps1 } catch [IO.IOException] { exit 0 }
    throw 'Second build acquired the checkout lock.'
} finally { $held.Dispose() }`)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("contended checkout: %v: %s", err, out)
		}
		if _, err := os.Stat(filepath.Join(root, "dist", "android")); !os.IsNotExist(err) {
			t.Fatalf("contending build touched output: %v", err)
		}
	}
}
