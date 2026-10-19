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

	core "bimeron/core"
	"bimeron/internal/telemetry"
)

const Version = 1
const maxRequest = 16 * 1024

type Request struct {
	ID      string `json:"id,omitempty"`
	Version int    `json:"version"`
	Command string `json:"command"`
	Config  string `json:"config,omitempty"`
	After   uint64 `json:"after,omitempty"`
}
type LoggedEvent struct {
	Sequence uint64     `json:"sequence"`
	Event    core.Event `json:"event"`
}
type Response struct {
	Core     *core.BuildDetails `json:"core,omitempty"`
	ID       string             `json:"id,omitempty"`
	Instance string             `json:"instance"`
	Version  int                `json:"version"`
	Status   core.Status        `json:"status"`
	Error    string             `json:"error,omitempty"`
	Events   []LoggedEvent      `json:"events,omitempty"`
	Cursor   uint64             `json:"cursor,omitempty"`
	Dropped  bool               `json:"dropped,omitempty"`

	Stats        *telemetry.Snapshot `json:"stats,omitempty"`
	Capabilities *core.Capabilities  `json:"capabilities,omitempty"`
}
type Engine interface {
	Start(context.Context, core.SessionConfig) error
	Stop(context.Context) error
	Status() core.Status
	Events() <-chan core.Event
	Stats() telemetry.Snapshot
}
type Server struct {
	instance string
	engine   Engine
	command  sync.Mutex
	mu       sync.Mutex
	history  []LoggedEvent
	sequence uint64
	load     func(string) (core.SessionConfig, error)
	shutdown context.CancelFunc
	closing  bool // protected by command
}

func NewServer(e Engine) *Server {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic("cannot create control instance")
	}
	return &Server{instance: fmt.Sprintf("%x", id), engine: e, load: core.LoadConfig}
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
		cancel()
		_ = l.Close()
		workers.Wait()
		result = errors.Join(result, s.engine.Stop(context.Background()))
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
	} else {
		switch r.Command {
		case "hello", "version":
			if r.Config != "" || r.After != 0 {
				answer.Error = "invalid_request"
				break
			}
			c := core.PlatformCapabilities()
			answer.Capabilities = &c
			build := core.GetBuildInfo()
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
			} else if err = s.engine.Start(ctx, cfg); err != nil {
				answer.Error = "session_start_failed"
				if errors.Is(err, core.ErrSessionRunning) {
					answer.Error = "session_already_running"
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
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(io.LimitReader(c, maxRequest+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > maxRequest {
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
	answer := s.dispatch(ctx, r)
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = json.NewEncoder(c).Encode(answer)
	if r.Command == "shutdown" && answer.Error == "" && s.shutdown != nil {
		s.shutdown()
	}
}
