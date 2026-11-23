//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"bimeron/internal/control"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

var restoreSourceSHA, restoreTargetSHA, restoreTargetVersion string

func guardedRepairSession(conn net.Conn, identity string, r heldRestoreRequest) error {
	p := unknownRestore(r.Operation)
	stage := "inspect"
	send := func(done bool) error {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		event := map[string]any{"version": 2, "operation_id": r.Operation, "stage": stage, "done": done}
		if done {
			event["outcome"] = p.Outcome
			event["current_state"] = p.CurrentState
			event["code"] = p.Code
		}
		return json.NewEncoder(conn).Encode(event)
	}
	defer func() { _ = send(true) }()
	if !r.Disruption || !r.Recovery || !restoreHex(restoreSourceSHA, 64) || !restoreHex(restoreTargetSHA, 64) || r.Target.SHA256 != restoreTargetSHA || r.Target.Version != restoreTargetVersion {
		return errors.New("guarded repair not authorized")
	}
	backend, err := newRepairBackend(identity)
	if err != nil {
		return err
	}
	b := backend.(*windowsRepairBackend)
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	b.service, err = b.manager.OpenService(serviceName)
	if err != nil {
		return err
	}
	if err = b.validateIdentity(); err != nil {
		return err
	}
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return err
	}
	directory := filepath.Join(root, "Bimeron Core")
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	source := filepath.Join(filepath.Dir(exe), "target", "bimeron.exe")
	unlock, err := control.LockRepairImage(source)
	if err != nil {
		return err
	}
	defer unlock()
	hash, err := regularFileSHA256(source)
	if err != nil || hash != restoreTargetSHA {
		return errors.New("target integrity mismatch")
	}
	installed := filepath.Join(directory, "bimeron.exe")
	hash, err = regularFileSHA256(installed)
	if err != nil || hash != restoreSourceSHA {
		return errors.New("source integrity mismatch")
	}
	matches := func(instance string) bool {
		a, err := control.CallService(ctx, control.Request{Version: 1, Command: "hello"})
		return err == nil && a.Instance == instance && a.Status.HasUpdateHold() && a.Status.ResidualProfile == r.Profile && a.Status.ResidualGeneration == r.Generation
	}
	if !matches(r.Instance) {
		return errors.New("stale update hold")
	}
	broker, err := regularFileSHA256(exe)
	if err != nil {
		return err
	}
	created, err := processCreated(uint32(os.Getpid()))
	if err != nil {
		return err
	}
	i := restoreIntent{r, b.owner, restoreSourceSHA, broker, uint32(os.Getpid()), created}
	if err = publishRestoreRecord(directory, r.Operation, "intent", i); err != nil {
		return err
	}
	stage = "replace"
	if err = send(false); err != nil {
		return err
	}
	expect := updateExpectation{source: source, version: r.Target.Version, sha256: restoreTargetSHA, keepKillSwitch: true}
	if err = updateWindowsServiceGuarded(ctx, b.service, expect, false, &i); err != nil {
		return err
	}
	state, err := b.service.Query()
	if err != nil || state.State != svc.Running {
		return errors.New("target unavailable")
	}
	a, err := control.CallService(ctx, control.Request{Command: "hello"})
	if err != nil || a.Instance == r.Instance || a.Core == nil || a.Core.Version != r.Target.Version || a.Capabilities == nil || a.Capabilities.GuardedRestoreContract != 1 || !matches(a.Instance) {
		return errors.New("target hold unverified")
	}
	hash, err = regularFileSHA256(installed)
	if err != nil || hash != restoreTargetSHA {
		return errors.New("installed target mismatch")
	}
	stage = "recover"
	if err = send(false); err != nil {
		return err
	}
	ans, err := control.CallServiceReadiness(ctx, state.ProcessId, control.Request{Command: "finalize_restore", ID: r.Operation, Instance: a.Instance, Operation: r.Operation, ResidualProfile: r.Profile, ResidualGeneration: r.Generation, TargetSHA: r.Target.SHA256})
	if err != nil {
		return err
	}
	if ans.Instance != a.Instance || ans.Restore == nil || ans.Restore.Operation != r.Operation {
		return errors.New("restore outcome unconfirmed")
	}
	p = *ans.Restore
	if p.Outcome != "restored" {
		return errors.New("restore outcome unconfirmed")
	}
	stage = "ready"
	return nil
}
