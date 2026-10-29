//go:build windows

package windowsnet

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
)

// PowerShellCommand runs only embedded Core scripts with Windows-shipped
// modules. Neither inherited SystemRoot/PATH nor user module autoloading may
// redirect a privileged operation. The caller retains its cancellation policy.
func PowerShellCommand(ctx context.Context, body string) (*exec.Cmd, error) {
	root, err := windows.GetWindowsDirectory()
	if err != nil {
		return nil, errors.New("Windows PowerShell unavailable")
	}
	system := filepath.Join(root, "System32")
	home := filepath.Join(system, "WindowsPowerShell", "v1.0")
	modules := filepath.Join(home, "Modules")
	// Windows PowerShell can expand PSModulePath at startup. Reset it inside the
	// script before the first autoloaded cmdlet, as well as in the child environment.
	prefix := "$env:PSModulePath=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString([]byte(modules)) + "'));\n"
	units := utf16.Encode([]rune(prefix + body))
	encoded := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(encoded[2*i:], u)
	}
	cmd := exec.CommandContext(ctx, filepath.Join(home, "powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	cmd.Dir = home
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// Do not forward arbitrary application tokens, proxy credentials, PowerShell
	// startup overrides or other unrelated environment variables to the child.
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(key) {
		case "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "USERNAME", "USERDOMAIN", "HOMEDRIVE", "HOMEPATH", "PROGRAMDATA", "ALLUSERSPROFILE", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432", "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)", "COMMONPROGRAMW6432", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "OS":
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "SystemRoot="+root, "WINDIR="+root, "ComSpec="+filepath.Join(system, "cmd.exe"), "PATH="+system+";"+root+";"+home, "PSModulePath="+modules)
	return cmd, nil
}
