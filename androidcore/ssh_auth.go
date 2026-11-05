package androidcore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"unicode"
	"unicode/utf8"

	"bimeron/internal/sshtunnel"
)

var errAuth = errors.New("SSH authentication request unavailable")

type authRequest struct {
	SessionID string   `json:"sessionId"`
	RequestID string   `json:"requestId"`
	Kind      string   `json:"kind"`
	Prompts   []string `json:"prompts"`
	Echo      []bool   `json:"echo"`
	ctx       context.Context
	cancel    context.CancelFunc
	result    chan []string
}
type authBridge struct {
	mu         sync.Mutex
	id         string
	pending    *authRequest
	generation uint64
	stopped    bool
}

func opaqueID() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("random source unavailable")
	}
	return hex.EncodeToString(b[:])
}
func safePrompt(s string) bool {
	if !utf8.ValidString(s) || len(s) > 1024 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}
func (b *authBridge) invalidate(g uint64, stopped bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.generation = g
	b.stopped = b.stopped || stopped
	if b.pending != nil {
		b.pending.cancel()
		b.pending = nil
	}
}
func (b *authBridge) prompt(g uint64) sshtunnel.Prompt {
	return func(ctx context.Context, c sshtunnel.Challenge) ([]string, error) {
		if len(c.Prompts) < 1 || len(c.Prompts) > 8 || len(c.Echo) != len(c.Prompts) {
			return nil, errAuth
		}
		switch c.Kind {
		case "password", "key_passphrase", "keyboard_interactive":
		default:
			return nil, errAuth
		}
		for _, p := range c.Prompts {
			if !safePrompt(p) {
				return nil, errAuth
			}
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		r := &authRequest{SessionID: b.id, RequestID: opaqueID(), Kind: c.Kind, Prompts: append([]string(nil), c.Prompts...), Echo: append([]bool(nil), c.Echo...), ctx: ctx, cancel: cancel, result: make(chan []string, 1)}
		data, _ := json.Marshal(r)
		if len(data) > 16384 {
			return nil, errAuth
		}
		b.mu.Lock()
		if b.stopped || b.generation != g || ctx.Err() != nil || b.pending != nil {
			b.mu.Unlock()
			return nil, errAuth
		}
		b.pending = r
		b.mu.Unlock()
		defer func() {
			b.mu.Lock()
			if b.pending == r {
				b.pending = nil
			}
			b.mu.Unlock()
		}()
		select {
		case answers := <-r.result:
			if ctx.Err() != nil {
				return nil, errAuth
			}
			return answers, nil
		case <-ctx.Done():
			return nil, errAuth
		}
	}
}

// PendingAuth returns a transient challenge, or JSON null.
func (s *Session) PendingAuth() string {
	b := &s.auth
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pending == nil {
		return "null"
	}
	if b.pending.ctx.Err() != nil {
		b.pending = nil
		return "null"
	}
	data, _ := json.Marshal(b.pending)
	return string(data)
}

// ReplyAuth consumes a request exactly once. Answers must be a JSON string array.
func (s *Session) ReplyAuth(sessionID, requestID, answersJSON string) error {
	if len(answersJSON) > 131072 || !utf8.ValidString(answersJSON) {
		return errAuth
	}
	var answers []string
	if json.Unmarshal([]byte(answersJSON), &answers) != nil || len(answers) < 1 || len(answers) > 8 {
		return errAuth
	}
	total := 0
	for _, v := range answers {
		if len(v) > 4096 || !utf8.ValidString(v) {
			return errAuth
		}
		total += len(v)
	}
	if total > 16384 {
		return errAuth
	}
	b := &s.auth
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.pending
	if r == nil || r.ctx.Err() != nil || r.SessionID != sessionID || r.RequestID != requestID || len(answers) != len(r.Prompts) {
		return errAuth
	}
	b.pending = nil
	r.result <- answers
	return nil
}

// CancelAuth consumes a request and terminates its SSH attempt.
func (s *Session) CancelAuth(sessionID, requestID string) error {
	b := &s.auth
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.pending
	if r == nil || r.ctx.Err() != nil || r.SessionID != sessionID || r.RequestID != requestID {
		return errAuth
	}
	b.pending = nil
	r.cancel()
	return nil
}
