//go:build windows

package windowsnet

import (
	bytespkg "bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

//go:embed manage.ps1
var script string

type Snapshot struct {
	IPv4      int      `json:"ipv4"`
	IPv6      int      `json:"ipv6"`
	Gateway4  string   `json:"gateway4"`
	Gateway6  string   `json:"gateway6"`
	Addresses string   `json:"addresses"`
	DNS       []string `json:"dns"`
}
type Config struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	Tag    string `json:"tag"`
	Index  int    `json:"index"`
	MTU    int    `json:"mtu"`
}
type SetupTiming struct {
	InterfaceMs int64 `json:"interfaceMs"`
	AddressesMs int64 `json:"addressesMs"`
	DNSMs       int64 `json:"dnsMs"`
	RoutesMs    int64 `json:"routesMs"`
	NRPTMs      int64 `json:"nrptMs"`
	CacheMs     int64 `json:"cacheMs"`
}

func run(ctx context.Context, c Config) ([]byte, error) { return executeScript(ctx, c, script) }
func executeScript(ctx context.Context, c Config, body string) ([]byte, error) {
	payload, _ := json.Marshal(c)
	// Payload contains validated network metadata only, never access keys.
	source := "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; trap { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }; $taskConfig = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(payload) + "')) | ConvertFrom-Json\n" + body
	units := utf16.Encode([]rune(source))
	bytes := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(bytes[i*2:], u)
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		return nil, fmt.Errorf("SystemRoot missing")
	}
	cmd := exec.CommandContext(ctx, filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(bytes))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var stderr bytespkg.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("network operation timed out or cancelled")
		}
		return nil, fmt.Errorf("Windows network operation failed: %s", strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
func Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
func Acquire() (func(), error) {
	runtime.LockOSThread()
	name, _ := windows.UTF16PtrFromString(`Global\BimeronCoreConnect`)
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("could not create VPN lock")
	}
	status, err := windows.WaitForSingleObject(handle, 0)
	if err != nil || (status != windows.WAIT_OBJECT_0 && status != windows.WAIT_ABANDONED) {
		_ = windows.CloseHandle(handle)
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("another bimeron VPN is running; stop it with Ctrl+C")
	}
	return func() { _ = windows.ReleaseMutex(handle); _ = windows.CloseHandle(handle); runtime.UnlockOSThread() }, nil
}
func Inspect(ctx context.Context, name string) (Snapshot, error) {
	return Observe(ctx, name, true)
}
func Observe(ctx context.Context, name string, startup bool) (Snapshot, error) {
	if startup {
		if _, err := run(ctx, Config{Action: "inspect", Name: name}); err != nil {
			return Snapshot{}, err
		}
	}
	return nativeObserve(ctx, name, startup)
}
func Configure(ctx context.Context, c Config) (SetupTiming, error) {
	if err := nativeBegin(c); err != nil {
		return SetupTiming{}, err
	}
	addressStart := time.Now()
	if err := nativeAddAddresses(c); err != nil {
		return SetupTiming{}, errors.Join(err, nativeCleanup(c))
	}
	addressMs := time.Since(addressStart).Milliseconds()
	c.Action = "setup"
	out, err := run(ctx, c)
	if err != nil {
		return SetupTiming{}, errors.Join(err, nativeCleanup(c))
	}
	var result struct {
		Index int `json:"index"`
		SetupTiming
	}
	if err := json.Unmarshal(out, &result); err != nil || result.Index != c.Index {
		return SetupTiming{}, errors.Join(fmt.Errorf("invalid tunnel interface index"), Cleanup(c))
	}
	routeStart := time.Now()
	if err := nativeAddRoutes(c); err != nil {
		return SetupTiming{}, errors.Join(err, Cleanup(c))
	}
	result.AddressesMs = addressMs
	result.RoutesMs = time.Since(routeStart).Milliseconds()
	return result.SetupTiming, nil
}
func Cleanup(c Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	c.Action = "cleanup"
	_, dnsErr := run(ctx, c)
	return errors.Join(dnsErr, nativeCleanup(c))
}
func Recover(ctx context.Context) error { _, err := run(ctx, Config{Action: "recover"}); return err }

// BoundDialer pins outbound sockets to the original physical interface. This
// prevents recursive tunnel capture for Outline and for direct policy routes.
func BoundDialer(s Snapshot) syscallControl {
	return func(network, address string, raw syscall.RawConn) error {
		var sockErr error
		err := raw.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				if s.IPv6 <= 0 {
					sockErr = fmt.Errorf("no physical IPv6 interface")
					return
				}
				sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 31, s.IPv6)
			} else {
				// IP_UNICAST_IF takes the interface index in network byte order.
				n := uint32(s.IPv4)
				n = (n&255)<<24 | (n&65280)<<8 | (n&16711680)>>8 | (n >> 24)
				sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(n))
			}
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}

type syscallControl func(string, string, syscall.RawConn) error
