package control

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	core "bimeron/core"
	"bimeron/internal/sshtunnel"
)

type experimentPromptResult struct {
	count int
	err   error
}

func experimentPrompt(t *testing.T, s *Server, ctx context.Context) (string, <-chan experimentPromptResult) {
	t.Helper()
	done := make(chan experimentPromptResult, 1)
	go func() {
		answers, err := s.prompt(ctx, sshtunnel.Challenge{Kind: "password", Prompts: []string{"Test input"}, Echo: []bool{false}})
		done <- experimentPromptResult{len(answers), err}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r := s.dispatch(context.Background(), Request{Version: Version, Command: "auth_pending"})
		if r.Auth != nil {
			return r.Auth.ID, done
		}
		runtime.Gosched()
	}
	t.Fatal("prompt was not published")
	return "", done
}

func experimentResult(t *testing.T, done <-chan experimentPromptResult) experimentPromptResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("prompt did not finish")
		return experimentPromptResult{}
	}
}

func experimentReply(s *Server, id string) Response {
	return s.dispatch(context.Background(), Request{Version: Version, Command: "auth_reply", ChallengeID: id, Answers: []string{"synthetic-test-value"}})
}

func TestSSHAuthLifecycleExperimentStaleAndReuse(t *testing.T) {
	s := NewServer(&fakeEngine{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old, done := experimentPrompt(t, s, ctx)
	cancel()
	if r := experimentResult(t, done); !errors.Is(r.err, context.Canceled) {
		t.Fatal("expected cancellation")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	current, done2 := experimentPrompt(t, s, ctx2)
	if experimentReply(s, old).Error != "invalid_auth_challenge" {
		t.Fatal("stale ID accepted")
	}
	if experimentReply(s, current).Error != "" {
		t.Fatal("current ID rejected")
	}
	if r := experimentResult(t, done2); r.err != nil || r.count != 1 {
		t.Fatal("reply was not delivered")
	}
	if experimentReply(s, current).Error != "invalid_auth_challenge" {
		t.Fatal("used ID accepted")
	}
}

// The Err barrier lets cancellation win the select before any reply is sent.
type experimentCanceledContext struct {
	context.Context
	observed chan struct{}
	release  chan struct{}
}

func (c *experimentCanceledContext) Err() error {
	close(c.observed)
	<-c.release
	return c.Context.Err()
}

func TestSSHAuthLifecycleExperimentCanceledCleanup(t *testing.T) {
	s := NewServer(&fakeEngine{})
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &experimentCanceledContext{base, make(chan struct{}), make(chan struct{})}
	id, done := experimentPrompt(t, s, ctx)
	cancel()
	select {
	case <-ctx.observed:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation was not observed")
	}
	// Cancellation has already won the prompt select. Err is held at a barrier,
	// so dispatch can deterministically consume the still-pending challenge.
	if experimentReply(s, id).Error != "" {
		t.Fatal("canceled challenge rejected before cleanup")
	}
	s.authMu.Lock()
	close(ctx.release) // Deferred cleanup cannot complete until authMu is released.
	select {
	case <-done:
		s.authMu.Unlock()
		t.Fatal("prompt completed while cleanup mutex was held")
	default:
	}
	s.authMu.Unlock()
	if r := experimentResult(t, done); !errors.Is(r.err, context.Canceled) || r.count != 0 {
		t.Fatal("accepted reply changed the canceled prompt result")
	}
	if experimentReply(s, id).Error != "invalid_auth_challenge" {
		t.Fatal("canceled challenge reused")
	}
}

func TestSSHAuthLifecycleExperimentConcurrentOneUse(t *testing.T) {
	s := NewServer(&fakeEngine{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id, done := experimentPrompt(t, s, ctx)
	const n = 16
	start := make(chan struct{})
	results := make(chan string, n)
	var workers sync.WaitGroup
	for i := 0; i < n; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); <-start; results <- experimentReply(s, id).Error }()
	}
	close(start)
	workers.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == "" {
			accepted++
		} else if err != "invalid_auth_challenge" {
			t.Fatal("unexpected reply error")
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted replies: %d", accepted)
	}
	if r := experimentResult(t, done); r.err != nil || r.count != 1 {
		t.Fatal("reply was not delivered")
	}
}

func TestSSHAuthLifecycleExperimentReplacementAndGuards(t *testing.T) {
	s := NewServer(&fakeEngine{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old, done := experimentPrompt(t, s, ctx)
	replacement := NewServer(&fakeEngine{})
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	id, done2 := experimentPrompt(t, replacement, ctx2)
	if experimentReply(replacement, old).Error != "invalid_auth_challenge" {
		t.Fatal("replacement accepted old ID")
	}
	for _, guard := range []Request{{Instance: s.instance}, {Session: "other-session"}, {Instance: s.instance, Session: "other-session"}} {
		guard.Version = Version
		guard.Command = "auth_reply"
		guard.ChallengeID = id
		guard.Answers = []string{"synthetic-test-value"}
		if replacement.dispatch(context.Background(), guard).Error != "invalid_request" {
			t.Fatal("guarded auth reply was not invalid_request")
		}
	}
	if experimentReply(replacement, id).Error != "" {
		t.Fatal("guard rejection consumed challenge")
	}
	experimentResult(t, done2)
	cancel()
	experimentResult(t, done)
}

// This fake deliberately owns no callback cancellation. It says nothing about real engine ownership.
type experimentCallbackEngine struct {
	fakeEngine
	prompt      sshtunnel.Prompt
	stopping    chan struct{}
	releaseStop chan struct{}
}

func (e *experimentCallbackEngine) Start(ctx context.Context, cfg core.SessionConfig) error {
	e.prompt = cfg.SSHPrompt
	return e.fakeEngine.Start(ctx, cfg)
}
func (e *experimentCallbackEngine) Stop(ctx context.Context) error {
	if e.stopping != nil {
		close(e.stopping)
		<-e.releaseStop
	}
	return e.fakeEngine.Stop(ctx)
}

func TestSSHAuthLifecycleExperimentFakeStopRestart(t *testing.T) {
	e := &experimentCallbackEngine{stopping: make(chan struct{}), releaseStop: make(chan struct{})}
	s := NewServer(e)
	s.load = func(string) (core.SessionConfig, error) { return core.SessionConfig{}, nil }
	path, err := filepath.Abs("unused-experiment.conf")
	if err != nil {
		t.Fatal("config path unavailable")
	}
	start := Request{Version: Version, Command: "start", Config: path}
	if s.dispatch(context.Background(), start).Error != "" || e.prompt == nil {
		t.Fatal("fake callback was not installed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan experimentPromptResult, 1)
	callback := e.prompt
	go func() {
		a, err := callback(ctx, sshtunnel.Challenge{Prompts: []string{"Test input"}, Echo: []bool{false}})
		done <- experimentPromptResult{len(a), err}
	}()
	var id string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r := s.dispatch(context.Background(), Request{Version: Version, Command: "auth_pending"})
		if r.Auth != nil {
			id = r.Auth.ID
			break
		}
		runtime.Gosched()
	}
	if id == "" {
		t.Fatal("fake callback did not publish challenge")
	}
	stopped := make(chan Response, 1)
	go func() { stopped <- s.dispatch(context.Background(), Request{Version: Version, Command: "stop"}) }()
	select {
	case <-e.stopping:
	case <-time.After(3 * time.Second):
		t.Fatal("fake stop did not reach barrier")
	}
	// Stop holds command admission; auth_reply independently consumes authMu.
	if experimentReply(s, "wrong-id").Error != "invalid_auth_challenge" {
		t.Fatal("wrong ID accepted during fake stop")
	}
	if experimentReply(s, id).Error != "" {
		t.Fatal("reply rejected during fake stop")
	}
	close(e.releaseStop)
	if (<-stopped).Error != "" {
		t.Fatal("fake stop failed")
	}
	if s.dispatch(context.Background(), start).Error != "" {
		t.Fatal("fake restart failed")
	}
	if experimentReply(s, id).Error != "invalid_auth_challenge" {
		t.Fatal("consumed callback reused after fake restart")
	}
	if r := experimentResult(t, done); r.err != nil || r.count != 1 {
		t.Fatal("fake callback did not receive reply")
	}
}

// Model only: pendingAuth has no expiry field. This represents the interval
// after a timer fires but before prompt's deferred removal acquires authMu.
// It does not execute the production two-minute timer.
func TestSSHAuthLifecycleExperimentExpiredPendingModel(t *testing.T) {
	s := NewServer(&fakeEngine{})
	p := &pendingAuth{challenge: AuthChallenge{ID: "modeled-expired", Challenge: sshtunnel.Challenge{Prompts: []string{"Test input"}, Echo: []bool{false}}}, reply: make(chan []string, 1)}
	s.pending = p
	if experimentReply(s, p.challenge.ID).Error != "" {
		t.Fatal("modeled expired pending entry was rejected")
	}
	if len(p.reply) != 1 || s.pending != nil {
		t.Fatal("modeled expired entry was not consumed atomically")
	}
	if experimentReply(s, p.challenge.ID).Error != "invalid_auth_challenge" {
		t.Fatal("modeled expired entry reused")
	}
}
