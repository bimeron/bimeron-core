//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"bimeron/core"
	"bimeron/internal/control"
	"bimeron/internal/windowsnet"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "BimeronCore"

type windowsService struct {
	owner  string
	listen func(string) (net.Listener, error)
}

func (h windowsService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending, WaitHint: 30000}
	log, _ := eventlog.Open(serviceName)
	if log != nil {
		defer log.Close()
	}
	listen := h.listen
	if listen == nil {
		listen = control.ListenService
	}
	l, err := listen(h.owner)
	if err != nil {
		if log != nil {
			log.Error(1, "control_listener_failed")
		}
		return true, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- control.NewServer(core.New(core.Options{})).Serve(ctx, l) }()
	status := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	changes <- status
	if log != nil {
		log.Info(1, "Service ready; VPN disconnected")
	}
	for {
		select {
		case err := <-done:
			if err != nil {
				if log != nil {
					log.Error(1, "service_cleanup_failed_run_recover")
				}
				return true, 2
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- status
			case svc.Stop, svc.Shutdown:
				cancel()
				status = svc.Status{State: svc.StopPending, WaitHint: 30000, CheckPoint: 1}
				changes <- status
			}
		case <-time.After(5 * time.Second):
			if status.State == svc.StopPending {
				status.CheckPoint++
				changes <- status
			}
		}
	}
}

func protectServiceDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || data.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("unsafe service directory")
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func serviceInstallDir() (string, error) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "Bimeron Core"), nil
}

// uninstallWindowsService removes the service and its artifacts. It also
// resumes an interrupted uninstall after the registration is already gone.
func uninstallWindowsService(m *mgr.Mgr) error {
	var deleteService func() error
	s, err := m.OpenService(serviceName)
	switch {
	case err == nil:
		defer s.Close()
		status, err := s.Query()
		if err != nil {
			return err
		}
		if status.State != svc.Stopped {
			return fmt.Errorf("stop service before uninstall")
		}
		deleteService = func() error {
			if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
				return err
			}
			return nil
		}
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		fmt.Println("Service is not registered; removing remaining files.")
	default:
		return err
	}
	return uninstallServiceArtifacts(deleteService, func() error { return eventlog.Remove(serviceName) }, func() error {
		dir, err := serviceInstallDir()
		if err != nil {
			return err
		}
		if err = protectServiceDir(dir); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		return removeServiceFiles(dir)
	})
}

func copyServiceFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("update source is not a regular file")
	}
	// Never follow a pre-existing destination link or overwrite a running installation.
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(destination)
	}
	return err
}

func parseWindowsUpdateAction(args []string) (updateExpectation, bool, error) {
	if args[0] == "update" {
		expect, err := parseUpdateExpectation(args[1:])
		return expect, true, err
	}
	if args[0] != "install" && len(args) != 1 {
		return updateExpectation{}, false, fmt.Errorf("unexpected service arguments")
	}
	return updateExpectation{}, false, nil
}

func serviceCommand(args []string) error { return serviceCommandForOwner(args, "") }
func serviceCommandForOwner(args []string, authenticatedOwner string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: bimeron service install [-automatic] | update -source <absolute-path> -version <version> -sha256 <executable-sha256> | describe | start | stop | status | uninstall")
	}
	if args[0] == "run" {
		if len(args) != 2 {
			return fmt.Errorf("invalid service arguments")
		}
		if _, err := windows.StringToSid(args[1]); err != nil {
			return fmt.Errorf("invalid service owner")
		}
		isService, err := svc.IsWindowsService()
		if err != nil || !isService {
			return fmt.Errorf("service run requires SCM")
		}
		return svc.Run(serviceName, windowsService{owner: args[1]})
	}
	if args[0] == "status" {
		if len(args) != 1 {
			return fmt.Errorf("unexpected service arguments")
		}
		manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
		if err != nil {
			return err
		}
		defer windows.CloseServiceHandle(manager)
		name, err := windows.UTF16PtrFromString(serviceName)
		if err != nil {
			return err
		}
		service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
		if err != nil {
			return err
		}
		defer windows.CloseServiceHandle(service)
		var status windows.SERVICE_STATUS
		if err = windows.QueryServiceStatus(service, &status); err != nil {
			return err
		}
		fmt.Printf("Service state: %s\n", formatServiceState(status.CurrentState))
		return nil
	}
	expect, updating, err := parseWindowsUpdateAction(args)
	if err != nil {
		return err
	}
	if !windowsnet.Elevated() {
		return fmt.Errorf("service management requires Administrator")
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if args[0] == "install" {
		f := flag.NewFlagSet("service install", flag.ContinueOnError)
		automatic := f.Bool("automatic", false, "start service at Windows boot (does not connect VPN)")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return fmt.Errorf("unexpected install arguments")
		}
		wantDLL, pinned := wintunDLLSHA256[runtime.GOARCH]
		if !pinned {
			return fmt.Errorf("no pinned Wintun DLL for %s", runtime.GOARCH)
		}
		existing, e := m.OpenService(serviceName)
		if e == nil {
			existing.Close()
			return fmt.Errorf("service already installed")
		}
		if e != windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return e
		}
		_, sid, err := currentServiceOwner()
		if authenticatedOwner != "" {
			if _, parseErr := windows.StringToSid(authenticatedOwner); parseErr != nil {
				return parseErr
			}
			sid = authenticatedOwner
		}
		if err != nil {
			return err
		}
		dir, err := serviceInstallDir()
		if err != nil {
			return err
		}
		if err = os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		if err = protectServiceDir(dir); err != nil {
			return err
		}
		// No service is registered, so installed files and the event source
		// can only be leftovers of an interrupted install or uninstall.
		if err = removeServiceFiles(dir); err != nil {
			return fmt.Errorf("cannot remove files left by a previous installation: %w", err)
		}
		if err = eventlog.Remove(serviceName); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("cannot remove event log source left by a previous installation: %w", err)
		}
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		dest := filepath.Join(dir, "bimeron.exe")
		if err = copyServiceFile(executable, dest); err != nil {
			return err
		}
		dll := filepath.Join(dir, "wintun.dll")
		// Verify the copies inside the protected directory against the pinned
		// release digests; the source folder may be writable by other users.
		if err = copyVerifiedServiceFile(filepath.Join(filepath.Dir(executable), "wintun.dll"), dll, wantDLL, copyServiceFile); err != nil {
			os.Remove(dest)
			return fmt.Errorf("cannot install pinned Wintun DLL: %w", err)
		}
		startType := uint32(mgr.StartManual)
		license := filepath.Join(dir, "WINTUN-LICENSE.txt")
		if err = copyVerifiedServiceFile(filepath.Join(filepath.Dir(executable), "WINTUN-LICENSE.txt"), license, wintunLicenseSHA256, copyServiceFile); err != nil {
			os.Remove(dest)
			os.Remove(dll)
			return fmt.Errorf("cannot install pinned Wintun license: %w", err)
		}
		if *automatic {
			startType = mgr.StartAutomatic
		}
		s, err := m.CreateService(serviceName, dest, mgr.Config{DisplayName: "Bimeron Core", Description: serviceDescription, StartType: startType, ServiceStartName: "LocalSystem"}, "service", "run", sid)
		if err != nil {
			os.Remove(dest)
			os.Remove(dll)
			os.Remove(license)
			return err
		}
		defer s.Close()
		if err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
			s.Delete()
			os.Remove(dest)
			os.Remove(dll)
			os.Remove(license)
			return err
		}
		if err = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}, {Type: mgr.ServiceRestart, Delay: 15 * time.Second}, {Type: mgr.NoAction}}, 86400); err != nil {
			s.Delete()
			eventlog.Remove(serviceName)
			os.Remove(dest)
			os.Remove(dll)
			os.Remove(license)
			return err
		}
		fmt.Println("Service installed. Start it with bimeron service start. VPN stays disconnected until start <config>.")
		return nil
	}
	if args[0] == "uninstall" {
		return uninstallWindowsService(m)
	}
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if updating {
		return updateWindowsService(s, expect)
	}
	switch args[0] {
	case "describe":
		config, err := s.Config()
		if err != nil {
			return err
		}
		config.Description = serviceDescription
		return s.UpdateConfig(config)
	case "start":
		return s.Start()
	case "stop":
		status, err := s.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		if _, err = s.Control(svc.Stop); err != nil {
			return err
		}
		deadline := time.Now().Add(2 * time.Minute)
		for time.Now().Before(deadline) {
			status, err = s.Query()
			if err != nil {
				return err
			}
			if status.State == svc.Stopped {
				return nil
			}
			time.Sleep(250 * time.Millisecond)
		}
		return fmt.Errorf("service stop timed out; cleanup may still be running")
	default:
		return fmt.Errorf("unknown service command")
	}
}
func currentServiceOwner() (string, string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", "", err
	}
	return "", u.User.Sid.String(), nil
}
