//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxServiceUnitRestrictsControlToOwner(t *testing.T) {
	unit := linuxServiceUnitText(1234)
	for _, want := range []string{
		"ExecStart=/usr/local/lib/bimeron/bimeron-core daemon",
		"Environment=BIMERON_CONTROL_UID=1234",
		"UMask=0077",
		"Restart=on-failure",
		"NoNewPrivileges=true",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit missing %q", want)
		}
	}
}

func TestLinuxServiceUnitAcceptedBySystemd(t *testing.T) {
	tool, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze is unavailable")
	}
	unit := strings.Replace(linuxServiceUnitText(1234), linuxServiceExecutable, "/bin/true", 1)
	path := filepath.Join(t.TempDir(), linuxServiceName)
	if err = os.WriteFile(path, []byte(unit), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(tool, "verify", path).CombinedOutput(); err != nil {
		t.Fatalf("invalid systemd unit: %v\n%s", err, output)
	}
}

func TestLinuxServiceStateCodes(t *testing.T) {
	for state, want := range map[string]string{
		"inactive": "1", "failed": "1", "activating": "2", "deactivating": "3", "active": "4",
	} {
		if got := linuxServiceStateCode(state); got != want {
			t.Fatalf("%s: got %s, want %s", state, got, want)
		}
	}
}

func TestCopyLinuxServiceFileIsExecutable(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	destination := filepath.Join(dir, "installed")
	if err := os.WriteFile(source, []byte("core"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyLinuxServiceFile(source, destination); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("installed core permissions", info, err)
	}
}
