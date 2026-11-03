//go:build windows

package windowsnet

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"strings"
)

// RecoveryPending observes only Core-owned DNS markers and never mutates policy.
func RecoveryPending(ctx context.Context) (bool, error) {
	cmd, err := PowerShellCommand(ctx, `$ErrorActionPreference='Stop'; $rules=@(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Comment -and ($_.Comment.StartsWith('BimeronCore:') -or $_.Comment -match '^BimeronIKEv2DNS:[a-f0-9]{32}$') }); if($rules.Count -gt 0){[Console]::Out.Write('pending')}else{[Console]::Out.Write('clear')}`)
	if err != nil {
		return false, err
	}
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(string(out)) {
	case "pending":
		return true, nil
	case "clear":
		return false, nil
	}
	return false, fmt.Errorf("invalid recovery observation")
}

// BeginRepairTransaction serializes bounded repair brokers independently of the
// VPN ownership lock. It never steals a live or abandoned transaction.
func BeginRepairTransaction() (func(), error) {
	runtime.LockOSThread()
	name, _ := windows.UTF16PtrFromString(`Global\BimeronCoreRepair`)
	h, err := createConnectMutex(name)
	if err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	result, err := windows.WaitForSingleObject(h, 0)
	if err != nil || result != windows.WAIT_OBJECT_0 {
		if result == windows.WAIT_ABANDONED {
			windows.ReleaseMutex(h)
		}
		windows.CloseHandle(h)
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("repair transaction busy or abandoned")
	}
	return func() { windows.ReleaseMutex(h); windows.CloseHandle(h); runtime.UnlockOSThread() }, nil
}
