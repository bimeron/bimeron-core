package control

import (
	"bimeron/core"
	"context"
	"sync"
	"time"
)

// validateForeground checks request shape and the current owner/session binding.
func (s *Server) validateForeground(r Request) Response {
	a := Response{ID: r.ID, Instance: s.instance, Version: Version, Status: s.engine.Status()}
	if r.Installation != s.installation {
		a.Error = "installation_mismatch"
		return a
	}
	if r.ID == "" || len(r.ID) > 64 || r.Config != "" || r.ChallengeID != "" || len(r.Answers) != 0 || r.PlanToken != "" {
		a.Error = "invalid_request"
		return a
	}
	if r.Version != Version {
		a.Error = "unsupported_protocol"
		return a
	}
	if r.Command != "hello" && r.AcceptRevision != "" {
		a.Error = "invalid_request"
		return a
	}
	if r.Command == "hello" && ((r.AcceptRevision == "" && r.Instance != "") || r.Session != "") {
		a.Error = "invalid_request"
		return a
	}
	if r.Command != "hello" && (r.Instance != s.instance || (a.Status.Session == nil && r.Session != "") || (a.Status.Session != nil && r.Session != a.Status.Session.ID)) {
		a.Error = "stale_instance"
		return a
	}
	if r.Command != "events" && r.After != 0 {
		a.Error = "invalid_request"
	}
	return a
}

func (s *Server) foregroundDispatcher(ctx context.Context, r Request) Response {
	a := s.validateForeground(r)
	if a.Error != "" {
		return a
	}
	switch r.Command {
	case "hello", "status", "events":
		answer := s.dispatch(ctx, r)
		if r.Command == "events" {
			if source, ok := s.engine.(interface{ EventDrops() uint64 }); ok {
				answer.SourceDrops = source.EventDrops()
				answer.Dropped = answer.Dropped || answer.SourceDrops != 0
			}
		}
		return answer
	case "stop":
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := s.engine.Stop(wait); err != nil {
			if wait.Err() != nil {
				a.Error = "cleanup_pending"
			} else {
				a.Error = "session_stop_failed"
			}
		}
		a.Status = s.engine.Status()
	case "close_owner":
		if (a.Status.State != core.Disconnected && a.Status.State != core.Failed) || (a.Status.Session != nil && a.Status.Session.Active) {
			a.Error = "session_not_terminal"
		}
	default:
		a.Error = "unknown_command"
	}
	return a
}

func (server *Server) bindForegroundSession(ctx context.Context, cfg core.SessionConfig) {
	server.foreground = true
	var launchMu sync.Mutex
	var launched, cancelled, closing bool
	var launchErr error
	server.foregroundDispatch = func(requestContext context.Context, r Request) Response {
		launchMu.Lock()
		// Status and session identity are refreshed under the same admission lock.
		a := server.validateForeground(r)
		if a.Error != "" {
			launchMu.Unlock()
			return a
		}
		if r.Command == "hello" && r.AcceptRevision != "" {
			if r.Instance != server.instance || r.After != 0 {
				a.Error = "invalid_request"
			} else if !server.acceptedRevision(r.AcceptRevision) {
				a.Error = "core_identity_mismatch"
			}
		}
		if a.Error != "" {
			launchMu.Unlock()
			return a
		}
		if closing {
			a.Error = "owner_closing"
			launchMu.Unlock()
			return a
		}
		switch r.Command {
		case "hello":
			if r.AcceptRevision != "" {
				if cancelled {
					a.Error = "activation_cancelled"
					launchMu.Unlock()
					return a
				}
				if !launched {
					launched = true
					// Start only validates/schedules; it does not wait for cleanup or call IPC.
					launchErr = server.engine.Start(ctx, cfg)
				}
			}
		case "stop":
			if !launched {
				cancelled = true
			}
		case "close_owner":
			if (a.Status.State != core.Disconnected && a.Status.State != core.Failed) || (a.Status.Session != nil && a.Status.Session.Active) {
				a.Error = "session_not_terminal"
			} else {
				closing = true
				a.closeAccepted = true
			}
			launchMu.Unlock()
			return a
		}
		failed := launchErr != nil
		launchMu.Unlock()
		// In particular Stop waits outside launchMu; Engine callbacks never need it.
		a = server.foregroundDispatcher(requestContext, r)
		if failed && a.Error == "" {
			a.Error = "session_start_failed"
		}
		return a
	}
}

func (s *Server) acceptedRevision(revision string) bool {
	if len(revision) != 40 {
		return false
	}
	for _, r := range revision {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	build := s.build()
	return build.Revision == revision && !build.Modified
}
