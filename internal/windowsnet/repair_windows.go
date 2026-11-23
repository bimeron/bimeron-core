//go:build windows

package windowsnet

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"strings"
)

const observeRecoveryDNS = `$ErrorActionPreference='Stop'
$rules = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object {
    $_.Comment -and ($_.Comment.StartsWith('BimeronCore:') -or $_.Comment -match '^BimeronIKEv2DNS:[a-f0-9]{32}$')
})
if ($rules.Count -gt 0) { [Console]::Out.Write('pending'); return }
`

const observeRecoveryRoutes = `$routes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
    $_.DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1','::/1','8000::/1'
})
if ($routes.Count -gt 0) { [Console]::Out.Write('pending') } else { [Console]::Out.Write('clear') }`

// RecoveryPending observes only Core-owned DNS markers and never mutates policy.
func RecoveryPending(ctx context.Context) (bool, error) {
	return readRecoveryPolicy(ctx, observeRecoveryDNS+"[Console]::Out.Write('clear')")
}

func readRecoveryPolicy(ctx context.Context, script string) (bool, error) {
	cmd, err := PowerShellCommand(ctx, script)
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

// RestoreNetworkPending also checks the four split-default routes installed by
// nativeAddRoutes. After a service replacement the process-local ownership table
// is gone. A matching foreign route prevents proof and must never be removed.
func RestoreNetworkPending(ctx context.Context) (bool, error) {
	return readRecoveryPolicy(ctx, observeRecoveryDNS+observeRecoveryRoutes)
}

// BeginServiceUpdate shares image replacement exclusion with conditional
// recovery. Only the existing updater may proceed after abandonment.
func BeginServiceUpdate(allowAbandoned bool) (func(), error) {
	runtime.LockOSThread()
	name, _ := windows.UTF16PtrFromString(`Global\BimeronCoreUpdate`)
	h, err := windows.CreateMutex(nil, false, name)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		runtime.UnlockOSThread()
		return nil, err
	}
	state, err := windows.WaitForSingleObject(h, 0)
	release := func() { windows.ReleaseMutex(h); windows.CloseHandle(h); runtime.UnlockOSThread() }
	if err == nil && state == windows.WAIT_ABANDONED && !allowAbandoned {
		release()
		return nil, fmt.Errorf("service update abandoned")
	}
	if err != nil || (state != windows.WAIT_OBJECT_0 && state != windows.WAIT_ABANDONED) {
		windows.CloseHandle(h)
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("another service update is running")
	}
	return release, nil
}
