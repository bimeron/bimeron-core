package control

import (
	"bimeron/core"
	"context"
	"sync"
	"time"
)

// foregroundDispatcher is deliberately separate from daemon dispatch. Launch
// supplies the only configuration; the IPC peer can never start another one.
func (s *Server) foregroundDispatcher(ctx context.Context, r Request) Response {
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
		if r.After != 0 {
			a.Error = "invalid_request"
			return a
		}
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
		if r.After != 0 {
			a.Error = "invalid_request"
			return a
		}
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
	var first sync.Once
	var launchMu sync.Mutex
	var launchErr error
	server.foregroundDispatch = func(requestContext context.Context, r Request) Response {
		if r.Installation != server.installation {
			return Response{Version: Version, ID: r.ID, Instance: server.instance, Error: "installation_mismatch", Status: server.engine.Status()}
		}
		launchMu.Lock()
		// Identity discovery is read-only. Activation binds approval of an exact
		// unmodified revision to this owner before any network mutation.
		if r.Command == "hello" && r.AcceptRevision != "" {
			if !server.acceptedRevision(r.AcceptRevision) {
				launchMu.Unlock()
				return Response{Version: Version, ID: r.ID, Instance: server.instance, Error: "core_identity_mismatch", Status: server.engine.Status()}
			}
			if r.Version == Version && r.ID != "" && len(r.ID) <= 64 && r.Config == "" && r.After == 0 && r.ChallengeID == "" && len(r.Answers) == 0 && r.PlanToken == "" && r.Instance == server.instance && r.Session == "" {
				first.Do(func() { launchErr = server.engine.Start(ctx, cfg) })
			} else {
				launchMu.Unlock()
				return Response{Version: Version, ID: r.ID, Instance: server.instance, Error: "invalid_request", Status: server.engine.Status()}
			}
		}

		failed := launchErr != nil
		launchMu.Unlock()
		a := server.foregroundDispatcher(requestContext, r)
		if failed && r.Command != "close_owner" {
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
