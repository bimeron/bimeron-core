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
	a := s.readinessResponse(r)
	json.NewEncoder(c).Encode(a)
}
func (s *Server) readinessResponse(r Request) Response {
	a := Response{Version: Version, Instance: s.instance}
	if r.Version != Version || (r.Command != "hello" && r.Command != "status") || r.ID != "" || r.Config != "" || r.After != 0 || r.Instance != "" || r.Session != "" || r.Installation != "" || r.AcceptRevision != "" || r.PlanToken != "" || r.ChallengeID != "" || len(r.Answers) != 0 {
		a.Error = "invalid_request"
		return a
	}
	if r.Command == "hello" {
		b := s.build()
		a.Core = &b
	} else {
		a.Status = core.Status{State: s.engine.Status().State}
	}
	return a
}
