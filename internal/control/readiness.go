package control

import (
	"bimeron/core"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// ServeReadiness exposes no command dispatch or profile/session details. The
// platform must restrict its listener to privileged maintenance principals.
func (s *Server) ServeReadiness(ctx context.Context, l net.Listener) error {
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.readinessConnection(ctx, c)
	}
}
func (s *Server) readinessConnection(ctx context.Context, c net.Conn) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(2 * time.Second)
	if err := c.SetDeadline(deadline); err != nil {
		return
	}
	var r Request
	var raw json.RawMessage
	if json.NewDecoder(io.LimitReader(c, 1024)).Decode(&raw) != nil || json.Unmarshal(raw, &r) != nil {
		return
	}
	if r.Command == "conditional_recovery" {
		if !validRecoveryWire(raw) || r.Version != Version || r.ID == "" || len(r.ID) > 64 {
			return
		}
		var peer ProcessWatch
		if s.PeerProcess != nil {
			peer = s.PeerProcess(c)
		}
		if peer != nil {
			defer peer.Close()
		}
		operation, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		disposition := s.recoverConditionally(operation, r.RecoveryIdentity, peer)
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		_ = json.NewEncoder(c).Encode(Response{Version: Version, ID: r.ID, Instance: s.instance, Disposition: disposition})
		return
	}
	if r.RecoveryIdentity != nil {
		return
	}
	if r.Command == "finalize_restore" {
		if s.FinalizeRestore == nil || s.PeerProcess == nil || !strictForegroundJSON(raw) || !strictRestoreKeys(raw, "version", "id", "command", "operation_id", "instance", "residual_profile", "residual_generation", "target_sha256") || r.Version != Version || r.Instance != s.instance || !restoreID(r.Operation) || len(r.ID) == 0 || len(r.ID) > 64 {
			return
		}
		peer := s.PeerProcess(c)
		if peer == nil {
			return
		}
		defer peer.Close()
		s.command.Lock()
		defer s.command.Unlock()
		if s.closing || !peer.Alive() {
			return
		}
		_ = c.SetDeadline(time.Time{})
		operation, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		proof := s.FinalizeRestore(operation, r, peer)
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		_ = json.NewEncoder(c).Encode(Response{Version: Version, ID: r.ID, Instance: s.instance, Restore: &proof})
		return
	}
	if r.Operation != "" || r.TargetSHA != "" {
		return
	}
	var peer ProcessWatch
	if (r.Command == "prepare_update" || r.Command == "commit_update") && s.PeerProcess != nil {
		peer = s.PeerProcess(c)
		if peer == nil {
			json.NewEncoder(c).Encode(Response{Version: Version, Instance: s.instance, Error: "update_hold_failed"})
			return
		}
	}
	s.replyReadiness(ctx, deadline, r, peer, json.NewEncoder(c).Encode)
}

// Serialize preparation and commit with other stop requests. A failed write must release
// the captured peer without publishing a hold for another stop to consume.
func (s *Server) replyReadiness(ctx context.Context, deadline time.Time, r Request, peer ProcessWatch, reply func(any) error) {
	if r.Command == "prepare_update" || r.Command == "commit_update" {
		s.command.Lock()
		defer s.command.Unlock()
	}
	defer func() {
		if peer != nil {
			peer.Close()
		}
	}()
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return
	}
	a := s.readinessAnswerFor(r)
	if r.Command == "commit_update" && a.Error == "" {
		h := s.hold
		if s.closing || s.UpdateCommitted == nil || h == nil || h.transaction != r.ID || !sameUpdateProcess(h.peer, peer) {
			a.Error = "update_hold_failed"
		} else if id, err := s.stopPreparedUpdateLocked(s.WriteUpdateHold); err != nil {
			a.Error = "update_hold_failed"
		} else {
			s.closing = true
			defer s.UpdateCommitted(id)
		}
	}
	var renewal func(string) error
	if a.Status.ResidualReason == core.ResidualUpdate && s.RenewUpdateHold != nil {
		renewal = s.RenewUpdateHold(a.Status.ResidualProfile)
	}
	a.Status.ResidualProfile = ""
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return
	}
	if r.Command == "prepare_update" && s.closing {
		a.Error = "update_hold_failed"
	}
	if r.Command == "prepare_update" && a.Error == "" {
		s.cancelUpdateHold()
	}
	if err := reply(a); err == nil && a.Error == "" && r.Command == "prepare_update" {
		s.armUpdateHold(&updateHold{until: s.now().Add(UpdateHoldWindow), peer: peer, transaction: a.UpdateTransaction, renew: renewal})
		peer = nil
	}
}

func (s *Server) readinessAnswerFor(r Request) Response {
	a := Response{Version: Version, Instance: s.instance}
	if r.Version != Version || (r.Command != "hello" && r.Command != "status" && r.Command != "prepare_update" && r.Command != "commit_update") || (r.Command != "prepare_update" && r.Command != "commit_update" && r.ID != "") || r.ResidualProfile != "" || r.ResidualGeneration != "" || r.Config != "" || r.After != 0 || r.Instance != "" || r.Session != "" || r.Installation != "" || r.AcceptRevision != "" || r.PlanToken != "" || r.ChallengeID != "" || len(r.Answers) != 0 {
		a.Error = "invalid_request"
		return a
	}
	switch r.Command {
	case "hello":
		b := s.build()
		a.Core = &b
		a.UpdateCommitSupported = s.UpdateCommitted != nil
	case "prepare_update", "commit_update":
		// The updater asks to keep kill switch protection on the next
		// service stop (ADR 0041). Only administrators reach this pipe.
		if len(r.ID) < 26 || len(r.ID) > 64 || strings.Trim(r.ID, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
			a.Error = "invalid_request"
			return a
		}
		a.ID = r.ID
		a.UpdateTransaction = r.ID
		if r.Command == "commit_update" {
			return a
		}
		status := s.engine.Status()
		a.Status = core.Status{State: status.State, KillSwitch: status.KillSwitch}
		if status.HasUpdateHold() {
			a.Status.ResidualReason = core.ResidualUpdate
			a.Status.ResidualProfile = status.ResidualProfile
		}
	default:
		a.Status = core.Status{State: s.engine.Status().State}
	}
	return a
}

// UpdateHoldWindow bounds the time between preparation and commit.
const UpdateHoldWindow = time.Minute

func (s *Server) CancelUpdatePreparation() {
	s.command.Lock()
	defer s.command.Unlock()
	s.closing = true
	s.cancelUpdateHold()
}

func sameUpdateProcess(a, b ProcessWatch) bool {
	first, ok := a.(interface{ ProcessID() uint32 })
	second, otherOK := b.(interface{ ProcessID() uint32 })
	return ok && otherOK && first.ProcessID() != 0 && first.ProcessID() == second.ProcessID() && a.Alive() && b.Alive()
}

func (s *Server) stopPreparedUpdateLocked(write func(string, string) error) (string, error) {
	h := s.hold
	s.hold = nil
	if h == nil {
		return "", errors.New("missing update preparation")
	}
	defer h.release()
	valid := func() bool { return s.now().Before(h.until) && h.peer != nil && h.peer.Alive() }
	engine, ok := s.engine.(interface {
		MarkPreparedUpdate(func(string) error, func() bool, func() error) error
	})
	if !ok || !valid() {
		return "", errors.New("invalid update preparation")
	}
	var renew func() error
	if h.renew != nil {
		renew = func() error { return h.renew(h.transaction) }
	}
	err := engine.MarkPreparedUpdate(func(profile string) error {
		if write == nil {
			return errors.New("update marker unavailable")
		}
		return write(profile, h.transaction)
	}, valid, renew)
	if err != nil {
		return "", err
	}
	s.abandonOnExit.Store(true)
	return h.transaction, nil
}

// ProcessWatch reports whether a process is still running.
type ProcessWatch interface {
	Alive() bool
	Close()
}

type updateHold struct {
	transaction string
	renew       func(string) error
	until       time.Time
	peer        ProcessWatch
}

func (h *updateHold) release() {
	if h.peer != nil {
		h.peer.Close()
	}
}

func (s *Server) armUpdateHold(h *updateHold) {
	old := s.hold
	s.hold = h
	if old != nil {
		old.release()
	}
}

func (s *Server) cancelUpdateHold() {
	old := s.hold
	s.hold = nil
	if old != nil {
		old.release()
	}
}
