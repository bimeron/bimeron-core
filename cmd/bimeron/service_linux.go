//go:build linux

package main

import (
	"debug/buildinfo"
	"debug/elf"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	linuxServiceName       = "bimeron-core.service"
	linuxServiceDir        = "/usr/local/lib/bimeron"
	linuxServiceExecutable = linuxServiceDir + "/bimeron-core"
	linuxServiceUnit       = "/etc/systemd/system/" + linuxServiceName
)

func linuxServiceUnitText(owner uint32) string {
	return fmt.Sprintf(`[Unit]
Description=Bimeron VPN core and local control
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=%s daemon
Environment=BIMERON_CONTROL_UID=%d
UMask=0077
Restart=on-failure
RestartSec=5s
TimeoutStopSec=120s
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`, linuxServiceExecutable, owner)
}

func linuxServiceOwner(explicit string) (uint32, error) {
	value := explicit
	if value == "" {
		value = os.Getenv("PKEXEC_UID")
	}
	if value == "" {
		value = os.Getenv("SUDO_UID")
	}
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("service owner must be a non-root UID; use -owner or run through sudo/pkexec")
	}
	return uint32(n), nil
}

func runSystemctl(args ...string) ([]byte, error) {
	output, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message != "" {
			return nil, fmt.Errorf("systemctl %s: %s", args[0], message)
		}
		return nil, fmt.Errorf("systemctl %s: %w", args[0], err)
	}
	return output, nil
}

func linuxServiceState() (string, error) {
	output, err := runSystemctl("show", "--no-pager", "--property=LoadState", "--property=ActiveState", linuxServiceName)
	if err != nil {
		return "", err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	if values["LoadState"] != "loaded" {
		return "", fmt.Errorf("service is not installed")
	}
	if values["ActiveState"] == "" {
		return "", fmt.Errorf("systemd returned no service state")
	}
	return values["ActiveState"], nil
}

func linuxServiceStateCode(state string) string {
	switch state {
	case "active":
		return "4"
	case "activating", "reloading":
		return "2"
	case "deactivating":
		return "3"
	default:
		return "1"
	}
}

func startLinuxService() error {
	if _, err := runSystemctl("start", linuxServiceName); err != nil {
		return err
	}
	state, err := linuxServiceState()
	if err != nil {
		return err
	}
	if state != "active" {
		return fmt.Errorf("service failed to start")
	}
	return nil
}

func stopLinuxService() error {
	if _, err := runSystemctl("stop", linuxServiceName); err != nil {
		return err
	}
	result, err := runSystemctl("show", "--no-pager", "--property=Result", "--value", linuxServiceName)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(result)) != "success" {
		return fmt.Errorf("service cleanup failed; run doctor/recover")
	}
	return nil
}

func requireLinuxRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("service management requires root; use sudo or pkexec")
	}
	return nil
}

func ensureLinuxServiceDir() error {
	if err := os.MkdirAll(linuxServiceDir, 0755); err != nil {
		return err
	}
	info, err := os.Lstat(linuxServiceDir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("unsafe service directory")
	}
	return nil
}

func copyLinuxServiceFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("invalid service executable")
	}
	out, err := os.CreateTemp(filepath.Dir(destination), ".bimeron-core-*")
	if err != nil {
		return err
	}
	name := out.Name()
	defer os.Remove(name)
	if err = out.Chmod(0755); err == nil {
		_, err = io.Copy(out, in)
	}
	if err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, destination)
}

func writeLinuxServiceUnit(owner uint32) error {
	temp, err := os.CreateTemp(filepath.Dir(linuxServiceUnit), ".bimeron-core-*.service")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err = temp.Chmod(0644); err == nil {
		_, err = io.WriteString(temp, linuxServiceUnitText(owner))
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, linuxServiceUnit)
}

func installLinuxService(owner uint32, automatic bool) error {
	if _, err := os.Lstat(linuxServiceUnit); err == nil {
		return fmt.Errorf("service already installed")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := ensureLinuxServiceDir(); err != nil {
		return err
	}
	source, err := os.Executable()
	if err != nil {
		return err
	}
	if err = copyLinuxServiceFile(source, linuxServiceExecutable); err != nil {
		return err
	}
	if err = writeLinuxServiceUnit(owner); err != nil {
		_ = os.Remove(linuxServiceExecutable)
		return err
	}
	if _, err = runSystemctl("daemon-reload"); err != nil {
		_ = os.Remove(linuxServiceUnit)
		_ = os.Remove(linuxServiceExecutable)
		return err
	}
	if automatic {
		if _, err = runSystemctl("enable", linuxServiceName); err != nil {
			_ = os.Remove(linuxServiceUnit)
			_ = os.Remove(linuxServiceExecutable)
			_, _ = runSystemctl("daemon-reload")
			return err
		}
	}
	fmt.Println("Service installed. Start it with bimeron service start. VPN stays disconnected until start <config>.")
	return nil
}

func updateLinuxService(expect updateExpectation) error {
	if err := ensureLinuxServiceDir(); err != nil {
		return err
	}
	installed, err := os.Lstat(linuxServiceExecutable)
	if err != nil {
		return err
	}
	owner, ok := installed.Sys().(*syscall.Stat_t)
	if !ok || !installed.Mode().IsRegular() || owner.Uid != 0 || installed.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("unsafe installed service executable")
	}
	state, err := linuxServiceState()
	if err != nil {
		return err
	}
	if state != "active" && state != "inactive" {
		return fmt.Errorf("wait for stable service state before updating")
	}
	updater, err := os.Executable()
	if err != nil {
		return err
	}
	updaterPath, _ := filepath.EvalSymlinks(updater)
	targetPath, _ := filepath.EvalSymlinks(linuxServiceExecutable)
	if updaterPath == targetPath {
		return fmt.Errorf("run service update from the trusted GUI package core, not the installed service")
	}
	sourcePath, _ := filepath.EvalSymlinks(expect.source)
	if sourcePath == targetPath {
		return fmt.Errorf("update source is the installed service")
	}
	currentELF, err := elf.Open(linuxServiceExecutable)
	if err != nil {
		return err
	}
	machine := currentELF.Machine
	currentELF.Close()
	staged := linuxServiceExecutable + ".update-new"
	backup := linuxServiceExecutable + ".update-old"
	if _, err = os.Lstat(backup); !os.IsNotExist(err) {
		return fmt.Errorf("previous update backup present; resolve it before retrying")
	}
	defer os.Remove(staged)
	if err = stageVerifiedUpdate(expect.source, staged, expect.sha256, copyLinuxServiceFile); err != nil {
		return err
	}
	info, err := buildinfo.ReadFile(staged)
	if err != nil || info.Path != "bimeron/cmd/bimeron" {
		return fmt.Errorf("invalid staged update binary")
	}
	newELF, err := elf.Open(staged)
	if err != nil {
		return err
	}
	newMachine := newELF.Machine
	newELF.Close()
	if machine != newMachine {
		return fmt.Errorf("update architecture differs from installed service")
	}
	wasRunning := state == "active"
	if wasRunning {
		if err = stopLinuxService(); err != nil {
			return fmt.Errorf("cannot update: %w", err)
		}
	}
	err = replaceServiceExecutable(linuxServiceExecutable, staged, backup, func() error {
		if !wasRunning {
			return nil
		}
		if err := startLinuxService(); err != nil {
			return err
		}
		return waitUpdatedService(expect.version)
	}, func() error {
		state, err := linuxServiceState()
		if err != nil {
			return err
		}
		if state == "inactive" {
			return nil
		}
		return stopLinuxService()
	})
	err = restorePreviousService(err, wasRunning, startLinuxService)
	if err != nil {
		return err
	}
	fmt.Println("Service updated; owner and startup settings preserved. VPN remains disconnected.")
	return nil
}

func uninstallLinuxService() error {
	state, err := linuxServiceState()
	if err != nil {
		return err
	}
	if state != "inactive" {
		return fmt.Errorf("stop service before uninstall")
	}
	if _, err = runSystemctl("disable", linuxServiceName); err != nil {
		return err
	}
	if err = os.Remove(linuxServiceUnit); err != nil {
		return err
	}
	if _, err = runSystemctl("daemon-reload"); err != nil {
		return err
	}
	if err = os.Remove(linuxServiceExecutable); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove(linuxServiceDir)
	return nil
}

func serviceCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: bimeron service install [-automatic] [-owner uid] | update -source <absolute-path> -version <version> -sha256 <executable-sha256> | describe | start | stop | status | uninstall")
	}
	if args[0] == "status" {
		if len(args) != 1 {
			return fmt.Errorf("unexpected service arguments")
		}
		state, err := linuxServiceState()
		if err != nil {
			return err
		}
		fmt.Printf("Service state: %s\n", linuxServiceStateCode(state))
		return nil
	}
	if args[0] == "describe" {
		if len(args) != 1 {
			return fmt.Errorf("unexpected service arguments")
		}
		data, err := os.ReadFile(linuxServiceUnit)
		if err != nil {
			return err
		}
		fmt.Print(string(data))
		return nil
	}
	if err := requireLinuxRoot(); err != nil {
		return err
	}
	if args[0] == "install" {
		flags := flag.NewFlagSet("service install", flag.ContinueOnError)
		automatic := flags.Bool("automatic", false, "start service at Linux boot (does not connect VPN)")
		ownerValue := flags.String("owner", "", "UID allowed to control the service")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected install arguments")
		}
		owner, err := linuxServiceOwner(*ownerValue)
		if err != nil {
			return err
		}
		return installLinuxService(owner, *automatic)
	}
	if args[0] == "update" {
		expect, err := parseUpdateExpectation(args[1:])
		if err != nil {
			return err
		}
		return updateLinuxService(expect)
	}
	if len(args) != 1 {
		return fmt.Errorf("unexpected service arguments")
	}
	switch args[0] {
	case "start":
		return startLinuxService()
	case "stop":
		return stopLinuxService()
	case "uninstall":
		return uninstallLinuxService()
	default:
		return fmt.Errorf("unknown service command")
	}
}
