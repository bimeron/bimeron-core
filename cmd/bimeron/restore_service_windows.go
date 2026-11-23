//go:build windows

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"

	"bimeron/core"
	"bimeron/internal/control"
	"time"

	"golang.org/x/sys/windows"
)

func restoreCaller(c net.Conn) (string, error) {
	fd, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return "", errors.New("unknown pipe peer")
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(fd.Fd()), &pid); err != nil {
		return "", err
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var token windows.Token
	if err = windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return "", err
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}
func processCreated(pid uint32) (uint64, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var created, exit, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(h, &created, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}
func unknownRestore(id string) control.RestoreProof {
	return control.RestoreProof{Version: 2, Operation: id, Outcome: "unknown", CurrentState: "unavailable", Code: "proof_unavailable"}
}

func wireRestoreService(s *control.Server, e *core.Engine, owner string, hold *core.UpdateHold) {
	directory := filepath.Dir(hold.Path)
	load := func(id string) (restoreIntent, error) {
		var i restoreIntent
		err := readRestoreRecord(directory, id, "intent", &i)
		if err == nil && (i.Owner != owner || i.Request.Operation != id || i.Request.Target.Version != core.GetBuildInfo().Version || i.Request.Target.Arch != core.GetBuildInfo().Architecture) {
			err = errors.New("intent identity mismatch")
		}
		if err == nil {
			exe, x := os.Executable()
			if x != nil {
				return i, x
			}
			hash, x := regularFileSHA256(exe)
			if x != nil || hash != i.Request.Target.SHA256 {
				err = errors.New("target mismatch")
			}
		}
		return i, err
	}
	query := func(ctx context.Context, id string) control.RestoreProof {
		p := unknownRestore(id)
		i, err := load(id)
		if err != nil {
			return p
		}
		var receipt restoreReceipt
		err = readRestoreRecord(directory, id, "receipt", &receipt)
		state := e.InspectRestoreProtection(ctx, i.Request.Profile, i.Request.Generation)
		p.CurrentState = state
		if os.IsNotExist(err) && state == "held" {
			p.Outcome = "held"
			p.CurrentState = "held"
			p.Code = "hold_verified"
			return p
		}
		if err != nil || receipt.Operation != id || receipt.Instance == "" || receipt.Target != i.Request.Target || receipt.Profile != i.Request.Profile || receipt.Generation != i.Request.Generation {
			return p
		}
		var claim string
		if state != "clear" || readRestoreRecord(directory, id, "claim", &claim) != nil || claim != receipt.Instance {
			return p
		}
		p.Outcome = "restored"
		p.CurrentState = "clear"
		p.Code = "commit_verified"
		return p
	}
	s.QueryRestore = func(c net.Conn, r control.Request) control.RestoreProof {
		sid, err := restoreCaller(c)
		if err != nil || sid != owner {
			return unknownRestore(r.Operation)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return query(ctx, r.Operation)
	}
	s.FinalizeRestore = func(ctx context.Context, r control.Request, peer control.ProcessWatch) control.RestoreProof {
		i, err := load(r.Operation)
		if err != nil {
			return unknownRestore(r.Operation)
		}
		verify := func() error {
			w, ok := peer.(interface{ ProcessID() uint32 })
			if !ok || !peer.Alive() || w.ProcessID() != i.BrokerPID {
				return errors.New("broker mismatch")
			}
			created, err := processCreated(i.BrokerPID)
			if err != nil || created != i.BrokerCreated {
				return errors.New("broker expired")
			}
			fresh, err := load(r.Operation)
			if err != nil || fresh != i || r.TargetSHA != i.Request.Target.SHA256 || r.ResidualProfile != i.Request.Profile || r.ResidualGeneration != i.Request.Generation {
				return errors.New("intent changed")
			}
			return nil
		}
		if err = verify(); err != nil {
			return unknownRestore(r.Operation)
		}
		// Persist a one-shot claim before cleanup. An interrupted attempt admits only a query.
		if err = publishRestoreRecord(directory, r.Operation, "claim", r.Instance); err != nil {
			return query(ctx, r.Operation)
		}
		err = e.FinalizeUpdateHold(ctx, r.ResidualProfile, r.ResidualGeneration, verify, func() error {
			return publishRestoreRecord(directory, r.Operation, "receipt", restoreReceipt{r.Operation, r.Instance, i.Request.Profile, i.Request.Generation, i.Request.Target})
		})
		_ = err // The postcondition is independently derived even if receipt publication failed.
		return query(ctx, r.Operation)
	}
}
