package control

import (
	"bimeron/core"
	"context"
	"encoding/json"
	"io"
	"net"
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
	c.SetDeadline(time.Now().Add(2 * time.Second))
	var r Request
	if json.NewDecoder(io.LimitReader(c, 1024)).Decode(&r) != nil {
		return
	}
	var peer ProcessWatch
	if r.Command == "prepare_update" && s.PeerProcess != nil {
		peer = s.PeerProcess(c)
		if peer == nil {
			json.NewEncoder(c).Encode(Response{Version: Version, Instance: s.instance, Error: "update_hold_failed"})
			return
		}
	}
	a := s.readinessAnswer(r, peer)
	json.NewEncoder(c).Encode(a)
}
func (s *Server) readinessResponse(r Request) Response { return s.readinessAnswer(r, nil) }

// readinessAnswer answers a readiness request; peer, when set, is the
// requesting process that a prepare_update hold is bound to.
func (s *Server) readinessAnswer(r Request, peer ProcessWatch) Response {
	a := Response{Version: Version, Instance: s.instance}
	if r.Version != Version || (r.Command != "hello" && r.Command != "status" && r.Command != "prepare_update") || r.ID != "" || r.Config != "" || r.After != 0 || r.Instance != "" || r.Session != "" || r.Installation != "" || r.AcceptRevision != "" || r.PlanToken != "" || r.ChallengeID != "" || len(r.Answers) != 0 {
		a.Error = "invalid_request"
		return a
	}
	switch r.Command {
	case "hello":
		b := s.build()
		a.Core = &b
	case "prepare_update":
		// The updater asks to keep kill switch protection on the next
		// service stop (ADR 0041). Only administrators reach this pipe.
		s.armUpdateHold(&updateHold{until: s.now().Add(UpdateHoldWindow), peer: peer})
		status := s.engine.Status()
		a.Status = core.Status{State: status.State, KillSwitch: status.KillSwitch}
	default:
		a.Status = core.Status{State: s.engine.Status().State}
	}
	return a
}

// UpdateHoldWindow bounds how long a prepare_update hold waits for the
// service stop it applies to.
const UpdateHoldWindow = time.Minute

// StopForUpdate is called by the service before it handles an SCM stop. When
// an unexpired prepare_update hold is armed, it consumes the hold, records
// the profile whose kill switch protection the run owns, marks the session
// abandoned so that its protection stays installed, and reports true. A
// user's stop that already ended the run leaves nothing to keep.
func (s *Server) StopForUpdate(record func(profileID string) error) (bool, error) {
	s.holdMu.Lock()
	hold := s.hold
	s.hold = nil
	s.holdMu.Unlock()
	if hold == nil {
		return false, nil
	}
	defer hold.release()
	// A hold whose updater is gone, for example killed after the request,
	// must not keep protection for somebody else's stop.
	if !s.now().Before(hold.until) || hold.peer != nil && !hold.peer.Alive() {
		return false, nil
	}
	var recordErr error
	status := s.engine.Status()
	if (status.KillSwitch == core.KillSwitchActive || status.KillSwitch == core.KillSwitchHolding) && status.Session != nil && status.Session.ProfileID != "" && record != nil {
		recordErr = record(status.Session.ProfileID)
	}
	s.AbandonOnExit()
	return true, recordErr
}

// ProcessWatch reports whether a process is still running.
type ProcessWatch interface {
	Alive() bool
	Close()
}

type updateHold struct {
	until time.Time
	peer  ProcessWatch
}

func (h *updateHold) release() {
	if h.peer != nil {
		h.peer.Close()
	}
}

func (s *Server) armUpdateHold(h *updateHold) {
	s.holdMu.Lock()
	old := s.hold
	s.hold = h
	s.holdMu.Unlock()
	if old != nil {
		old.release()
	}
}

func (s *Server) cancelUpdateHold() {
	s.holdMu.Lock()
	old := s.hold
	s.hold = nil
	s.holdMu.Unlock()
	if old != nil {
		old.release()
	}
}
