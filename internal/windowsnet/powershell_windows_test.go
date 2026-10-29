//go:build windows

package windowsnet

import (
	"context"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPowerShellCommandIgnoresInheritedExecutableAndSecrets(t *testing.T) {
	t.Setenv("SystemRoot", t.TempDir())
	t.Setenv("PATH", "untrusted-path")
	t.Setenv("PSModulePath", "untrusted-modules")
	t.Setenv("BIMERON_SECRET_SENTINEL", "do-not-forward")
	cmd, err := PowerShellCommand(context.Background(), "'read-only'")
	if err != nil {
		t.Fatal(err)
	}
	root, err := windows.GetWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0")
	if cmd.Path != filepath.Join(home, "powershell.exe") || cmd.Dir != home {
		t.Fatal("untrusted executable or working directory")
	}
	for _, entry := range cmd.Env {
		if strings.Contains(entry, "untrusted") || strings.Contains(entry, "do-not-forward") {
			t.Fatal("untrusted child environment forwarded")
		}
	}
}

// Imports command metadata only; it never executes Get-NetRoute or changes OS
// networking. A poisoned user module would write only the temporary marker.
func TestPowerShellCommandRejectsUserModuleAutoload(t *testing.T) {
	if strconv.IntSize != 64 {
		t.Skip("native 64-bit Windows module smoke test")
	}
	temp := t.TempDir()
	module := filepath.Join(temp, "NetTCPIP")
	if os.Mkdir(module, 0700) != nil {
		t.Fatal("fixture creation failed")
	}
	marker := filepath.Join(temp, "poison-executed")
	body := "[IO.File]::WriteAllText('" + strings.ReplaceAll(marker, "'", "''") + "','poison'); function Get-NetRoute { 'poison' }; Export-ModuleMember -Function Get-NetRoute"
	if os.WriteFile(filepath.Join(module, "NetTCPIP.psm1"), []byte(body), 0600) != nil {
		t.Fatal("fixture module write failed")
	}
	t.Setenv("PSModulePath", temp)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd, err := PowerShellCommand(ctx, `$ErrorActionPreference='Stop'; $c=Get-Command Get-NetRoute -ErrorAction Stop; if(-not $c.Module.ModuleBase.StartsWith($PSHOME+'\Modules',[StringComparison]::OrdinalIgnoreCase)){throw 'Untrusted module'}; [Console]::Out.Write('trusted-system-module')`)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate startup rewriting the environment. The trusted script prefix must
	// still prevent the user module from running before command discovery.
	for i, entry := range cmd.Env {
		key, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(key, "PSModulePath") {
			cmd.Env[i] = "PSModulePath=" + temp
		}
	}
	out, err := cmd.Output()
	if err != nil || string(out) != "trusted-system-module" {
		t.Fatal("trusted system module resolution failed")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("user module executed")
	}
}
