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
	goStub := "#!/bin/sh\nif [ \"$*\" != 'env -u=false -w=false -json=false -changed=false -n=false -x=false GOFLAGS GOEXPERIMENT' ]; then touch \"$MARKER\"; exit 0; fi\nprintf '%s' \"$SETTINGS\"\nexit \"$ENV_STATUS\"\n"
	goName, mobileName := "go", "gomobile"
	if windows {
		entries = []string{"build-all.ps1", "build-android.ps1", "install-wintun.ps1"}
		helper = "release-go.ps1"
		goName, mobileName = "go.cmd", "gomobile.cmd"
		goStub = "@echo off\r\nif not \"%*\"==\"env -u=false -w=false -json=false -changed=false -n=false -x=false GOFLAGS GOEXPERIMENT\" (type nul > \"%MARKER%\" & exit /b 0)\r\nif defined SETTINGS echo %SETTINGS%\r\nexit /b %ENV_STATUS%\r\n"
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

func TestReleasePreflightPreservesGOENV(t *testing.T) {
	bin := filepath.Join(runtime.GOROOT(), "bin")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOENV", "off")
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOEXPERIMENT", "")
	t.Setenv("GOWORK", "off")
	t.Setenv("BIMERON_VERSION", "v1.0.0")

	builder := filepath.Join(t.TempDir(), "build-dist")
	wrapper := "release-go.sh"
	if runtime.GOOS == "windows" {
		builder += ".exe"
		wrapper = "release-go.ps1"
	}
	wrapper, err := filepath.Abs(filepath.Join("..", "scripts", wrapper))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", builder, "./scripts/build-dist.go")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build distribution tool: %v: %s", err, out)
	}

	for _, entry := range []string{"wrapper", "build-dist"} {
		t.Run(entry, func(t *testing.T) {
			root := t.TempDir()
			config := filepath.Join(root, "goenv")
			const settings = "GOFLAGS=-u\nGOPROXY=off\n"
			if err := os.WriteFile(config, []byte(settings), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("GOENV", config)
			mod := filepath.Join(root, "go.mod")
			var cmd *exec.Cmd
			if entry == "wrapper" {
				// The requested action would create go.mod if the guard let it run.
				if runtime.GOOS == "windows" {
					cmd = exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", wrapper, "mod", "init", "example.org/release")
				} else {
					cmd = exec.Command("sh", wrapper, "mod", "init", "example.org/release")
				}
			} else {
				if err := os.WriteFile(mod, []byte("module example.org/release\n"), 0600); err != nil {
					t.Fatal(err)
				}
				cmd = exec.Command(builder, "linux")
			}
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			want := "unset goflags and goexperiment"
			if entry == "build-dist" {
				want = "goflags and goexperiment must be empty"
			}
			if err == nil || !strings.Contains(strings.ToLower(string(out)), want) {
				t.Errorf("expected settings refusal, got %v: %s", err, out)
			}
			if got, err := os.ReadFile(config); err != nil || string(got) != settings {
				t.Errorf("GOENV after preflight = %q, %v", got, err)
			}
			actionOutput := mod
			if entry == "build-dist" {
				actionOutput = filepath.Join(root, "bin")
			}
			if _, err := os.Stat(actionOutput); !os.IsNotExist(err) {
				t.Errorf("expected absent release output %s, got %v", actionOutput, err)
			}
		})
	}
}
