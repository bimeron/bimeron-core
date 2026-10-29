// Package control provides a bounded local RPC protocol for the shared core.
package control

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	core "bimeron/core"
	"bimeron/internal/sshtunnel"
	"bimeron/internal/systemvpn"
	"bimeron/internal/telemetry"
)

const Version = 1
const maxRequest = 16 * 1024

type Request struct {
	Installation   string   `json:"installation,omitempty"`
	AcceptRevision string   `json:"accept_revision,omitempty"`
	PlanToken      string   `json:"plan_token,omitempty"`
	Instance       string   `json:"instance,omitempty"`
	Session        string   `json:"session,omitempty"`
	ID             string   `json:"id,omitempty"`
	Version        int      `json:"version"`
	Command        string   `json:"command"`
	Config         string   `json:"config,omitempty"`
	After          uint64   `json:"after,omitempty"`
	ChallengeID    string   `json:"challenge_id,omitempty"`
	Answers        []string `json:"answers,omitempty"`
}
type AuthChallenge struct {
	ID string `json:"id"`
	sshtunnel.Challenge
}
type LoggedEvent struct {
	Sequence uint64     `json:"sequence"`
	Event    core.Event `json:"event"`
}
type Response struct {
	Installation string                 `json:"installation,omitempty"`
	SourceDrops  uint64                 `json:"source_drops,omitempty"`
	Owner        *ProcessIdentity       `json:"owner,omitempty"`
	Endpoint     string                 `json:"endpoint,omitempty"`
	Profile      *systemvpn.ProfilePlan `json:"profile,omitempty"`
	Operation    string                 `json:"operation,omitempty"`
	Core         *core.BuildDetails     `json:"core,omitempty"`
	ID           string                 `json:"id,omitempty"`
	Instance     string                 `json:"instance"`
	Version      int                    `json:"version"`
	Status       core.Status            `json:"status"`
	Error        string                 `json:"error,omitempty"`
	Events       []LoggedEvent          `json:"events,omitempty"`
	Cursor       uint64                 `json:"cursor,omitempty"`
	Dropped      bool                   `json:"dropped,omitempty"`

	Stats        *telemetry.Snapshot `json:"stats,omitempty"`
	Capabilities *core.Capabilities  `json:"capabilities,omitempty"`
	Auth         *AuthChallenge      `json:"auth,omitempty"`
}
type Engine interface {
	Start(context.Context, core.SessionConfig) error
	Stop(context.Context) error
	Status() core.Status
	Events() <-chan core.Event
	Stats() telemetry.Snapshot
}
type Server struct {
	installation       string
	build              func() core.BuildDetails
	foreground         bool
	owner              *ProcessIdentity
	endpoint           string
	authorize          func(net.Conn) (func(), error)
	foregroundDispatch func(context.Context, Request) Response
	instance           string
	engine             Engine
	command            sync.Mutex
	mu                 sync.Mutex
	history            []LoggedEvent
	sequence           uint64
	load               func(string) (core.SessionConfig, error)
	shutdown           context.CancelFunc
	closing            bool // protected by command
	authMu             sync.Mutex
	pending            *pendingAuth
}
type pendingAuth struct {
	challenge AuthChallenge
	reply     chan []string
}

func (s *Server) prompt(ctx context.Context, challenge sshtunnel.Challenge) ([]string, error) {
	if len(challenge.Prompts) == 0 || len(challenge.Prompts) > 8 || len(challenge.Prompts) != len(challenge.Echo) {
		return nil, fmt.Errorf("invalid SSH challenge")
	}
	for _, p := range challenge.Prompts {
		if !utf8.ValidString(p) || len(p) > 256 {
			return nil, fmt.Errorf("invalid SSH challenge")
		}
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("SSH challenge unavailable")
	}
	p := &pendingAuth{challenge: AuthChallenge{ID: fmt.Sprintf("%x", id), Challenge: challenge}, reply: make(chan []string, 1)}
	s.authMu.Lock()
	if s.pending != nil {
		s.authMu.Unlock()
		return nil, fmt.Errorf("SSH challenge already pending")
	}
	s.pending = p
	s.authMu.Unlock()
	defer func() {
		s.authMu.Lock()
		if s.pending == p {
			s.pending = nil
		}
		s.authMu.Unlock()
	}()
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	select {
	case answers := <-p.reply:
		return answers, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("SSH authentication timed out")
	}
}

func NewServer(e Engine) *Server {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic("cannot create control instance")
	}
	return &Server{build: core.GetBuildInfo, instance: fmt.Sprintf("%x", id), engine: e, load: core.LoadConfig}
}

// Serve owns listener and all clients. On daemon shutdown it waits for core
// cleanup even if a client or the daemon context has already been cancelled.
func (s *Server) Serve(ctx context.Context, l net.Listener) (result error) {
	ctx, cancel := context.WithCancel(ctx)
	s.shutdown = cancel
	defer cancel()
	var workers sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	defer func() {
		stopEngine := !s.foreground || ctx.Err() != nil
		cancel()
		_ = l.Close()
		workers.Wait()
		if stopEngine {
			result = errors.Join(result, s.engine.Stop(context.Background()))
		}
	}()
	slots := make(chan struct{}, 32)
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-s.engine.Events():
				if !ok {
					return
				}
				s.record(e)
			}
		}
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// A broken private control transport is not a disconnect request.
			// Keep the foreground owner/Engine/marker alive for explicit owner
			// cancellation; never recreate or fall back to another endpoint.
			if s.foreground {
				<-ctx.Done()
			}
			return fmt.Errorf("control listener failed")
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		workers.Add(1)
		go func() { defer workers.Done(); defer func() { <-slots }(); s.handle(ctx, c) }()
	}
}
func (s *Server) record(e core.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sequence++
	s.history = append(s.history, LoggedEvent{s.sequence, e})
	if len(s.history) > 128 {
		s.history = append([]LoggedEvent(nil), s.history[len(s.history)-128:]...)
	}
}
func (s *Server) dispatch(ctx context.Context, r Request) Response {
	answer := Response{Version: Version, ID: r.ID, Instance: s.instance}
	if len(r.ID) > 64 {
		answer.Error = "invalid_request"
		answer.ID = ""
		answer.Status = s.engine.Status()
		return answer
	}
	if r.Version != Version {
		answer.Error = "unsupported_protocol"
	} else if !s.foreground && (r.Installation != "" || r.Instance != "" || r.Session != "" || r.PlanToken != "" || r.AcceptRevision != "") {
		answer.Error = "invalid_request"
	} else if r.Command != "auth_reply" && (r.ChallengeID != "" || len(r.Answers) != 0) {
		answer.Error = "invalid_request"
	} else {
		switch r.Command {
		case "hello", "version":
			if r.Config != "" || r.After != 0 {
				answer.Error = "invalid_request"
				break
			}
			c := core.PlatformCapabilities()
			answer.Capabilities = &c
			build := s.build()
			answer.Core = &build
		case "status":
			if r.Config != "" || r.After != 0 {
				answer.Error = "invalid_request"
			}
		case "stats":
			if r.Config != "" || r.After != 0 {
				answer.Error = "invalid_request"
				break
			}
			snapshot := s.engine.Stats()
			answer.Stats = &snapshot
		case "capabilities":
			if r.Config != "" || r.After != 0 {
				answer.Error = "invalid_request"
				break
			}
			c := core.PlatformCapabilities()
			answer.Capabilities = &c
		case "events":
			if r.Config != "" {
				answer.Error = "invalid_request"
				break
			}
			s.mu.Lock()
			answer.Cursor = s.sequence
			if r.After > s.sequence {
				answer.Error = "invalid_cursor"
			} else {
				if len(s.history) > 0 && r.After < s.history[0].Sequence-1 {
					answer.Dropped = true
				}
				for _, e := range s.history {
					if e.Sequence > r.After {
						answer.Events = append(answer.Events, e)
					}
				}
			}
			s.mu.Unlock()
		case "auth_pending":
			if r.Config != "" || r.After != 0 || r.ChallengeID != "" || len(r.Answers) != 0 {
				answer.Error = "invalid_request"
				break
			}
			s.authMu.Lock()
			if s.pending != nil {
				copy := s.pending.challenge
				answer.Auth = &copy
			}
			s.authMu.Unlock()
		case "auth_reply":
			if r.Config != "" || r.After != 0 || r.ChallengeID == "" {
				answer.Error = "invalid_request"
				break
			}
			s.authMu.Lock()
			p := s.pending
			if p == nil || p.challenge.ID != r.ChallengeID || len(r.Answers) != len(p.challenge.Prompts) {
				answer.Error = "invalid_auth_challenge"
			} else {
				for _, value := range r.Answers {
					if len(value) > 1024 || !utf8.ValidString(value) {
						answer.Error = "invalid_auth_response"
						break
					}
				}
				if answer.Error == "" {
					s.pending = nil
					p.reply <- append([]string(nil), r.Answers...)
				}
			}
			s.authMu.Unlock()
		case "start":
			if !filepath.IsAbs(r.Config) || r.After != 0 {
				answer.Error = "absolute_config_path_required"
				break
			}
			s.command.Lock()
			if s.closing {
				answer.Error = "daemon_shutting_down"
				s.command.Unlock()
				break
			}
			cfg, err := s.load(r.Config)
			if err != nil {
				answer.Error = "invalid_configuration"
			} else {
				if cfg.IKEv2 != nil {
					answer.Error = "ikev2_requires_foreground_user_session"
					s.command.Unlock()
					break
				}
				cfg.SSHPrompt = s.prompt
				cfg.SSHDefaultKeys = false // Service home is not the GUI user's home.
				if err = s.engine.Start(ctx, cfg); err != nil {
					answer.Error = "session_start_failed"
					if errors.Is(err, core.ErrSessionRunning) {
						answer.Error = "session_already_running"
					}
				}
			}
			s.command.Unlock()
		case "stop", "shutdown":
			if r.Config != "" || r.After != 0 {
				answer.Error = "invalid_request"
				break
			}
			s.command.Lock()
			if err := s.engine.Stop(ctx); err != nil {
				answer.Error = "session_stop_failed"
			} else if r.Command == "shutdown" {
				s.closing = true
			}
			s.command.Unlock()
		default:
			answer.Error = "unknown_command"
		}
	}
	answer.Status = s.engine.Status()
	return answer
}
func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	if s.authorize != nil {
		release, err := s.authorize(c)
		if err != nil {
			return
		}
		defer release()
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(io.LimitReader(c, maxRequest+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > maxRequest {
		return
	}
	if s.foreground && !strictForegroundJSON(line) {
		return
	}
	var r Request
	decoder := json.NewDecoder(bytesReader(line))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil {
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return
	}
	var answer Response
	if s.foregroundDispatch != nil {
		answer = s.foregroundDispatch(ctx, r)
	} else {
		answer = s.dispatch(ctx, r)
	}
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	answer.Owner = s.owner
	answer.Installation = s.installation
	answer.Endpoint = s.endpoint
	encoded, encodeErr := json.Marshal(answer)
	if encodeErr != nil || len(encoded)+1 > 256*1024 {
		answer = Response{Installation: s.installation, ID: r.ID, Version: Version, Instance: s.instance, Owner: s.owner, Endpoint: s.endpoint, Error: "response_too_large"}
		encoded, _ = json.Marshal(answer)
	}
	_, _ = c.Write(append(encoded, '\n'))
	if (r.Command == "shutdown" || (s.foreground && r.Command == "close_owner")) && answer.Error == "" && s.shutdown != nil {
		s.shutdown()
	}
}
