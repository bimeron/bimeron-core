package control

import (
	"bimeron/core"
	"bytes"
	"context"
	"time"
	"unicode/utf8"
)

type ikeAuthorityKey struct{}
type ikeBinding struct{ installation, instance, session, attempt, request, profile, server string }
type ikeAuth struct {
	generation uint64
	owner      *Server
	live       bool
	used       bool
	binding    ikeBinding
	deadline   time.Time
	consume    func([]byte, []byte)
	timer      *time.Timer
}

func (s *Server) ikeAuthority(ctx context.Context) (context.Context, func()) {
	s.ikeMu.Lock()
	a := &ikeAuth{owner: s, live: true, generation: s.ikeGeneration}
	s.ikeMu.Unlock()
	retire := func() { s.ikeMu.Lock(); a.live = false; s.retireIKEAuthLocked(a); s.ikeMu.Unlock() }
	stop := context.AfterFunc(ctx, retire)
	return context.WithValue(ctx, ikeAuthorityKey{}, a), func() { stop(); retire() }
}

// Caller holds ikeMu. Timer.Stop never waits for a running callback.
func (s *Server) retireIKEAuthLocked(a *ikeAuth) {
	a.consume = nil
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	if s.ikePending == a {
		s.ikePending = nil
	}
}

func validIKEField(v string) bool {
	return len(v) > 0 && len(v) <= 256 && utf8.ValidString(v) && !bytes.ContainsRune([]byte(v), 0)
}

// beginIKEAuth is a private offline fixture seam. No production caller installs a consumer.
func (s *Server) beginIKEAuth(ctx context.Context, b ikeBinding, ttl time.Duration, consume func([]byte, []byte)) bool {
	a, _ := ctx.Value(ikeAuthorityKey{}).(*ikeAuth)
	if a == nil || a.owner != s {
		return false
	}
	s.ikeMu.Lock()
	defer s.ikeMu.Unlock()
	if !s.ikeLifecycleLocked(a, b) || ctx.Err() != nil || a.owner != s || !a.live || a.used || consume == nil || ttl <= 0 || ttl > 2*time.Minute {
		return false
	}
	for _, v := range []string{b.installation, b.instance, b.session, b.attempt, b.request, b.profile, b.server} {
		if !validIKEField(v) {
			return false
		}
	}
	if s.ikePending != nil || b.installation != s.installation || b.instance != s.instance {
		return false
	}
	a.used = true
	a.binding = b
	a.deadline = time.Now().Add(ttl)
	a.consume = consume
	s.ikePending = a
	a.timer = time.AfterFunc(ttl, func() {
		s.ikeMu.Lock()
		defer s.ikeMu.Unlock()
		s.retireIKEAuthLocked(a)
	})
	return true
}

type ikeIntent uint8

const (
	ikePassword ikeIntent = iota
	ikeCertificate
	ikeSmartCard
)

type ikeStorage uint8

const (
	ikeAttemptOnly ikeStorage = iota
	ikeWindowsStorage
)

type ikeResult struct {
	accepted bool
	storage  string
}
type ikeSecrets struct{ username, password []byte }

func (ikeSecrets) String() string   { return "[redacted]" }
func (ikeSecrets) GoString() string { return "[redacted]" }

// Ownership of both buffers transfers even on rejection. The synchronous fixture
// must not retain aliases. Acceptance is never a native authentication result.
// Fixtures must be synchronous and non-reentrant: they must not call Server
// methods or wait for retirement. Holding ikeMu linearizes dispatch with retirement.
func (s *Server) answerIKEAuth(ctx context.Context, b ikeBinding, intent ikeIntent, storage ikeStorage, secrets ikeSecrets) ikeResult {
	defer clear(secrets.username)
	defer clear(secrets.password)
	result := ikeResult{storage: "not_requested"}
	if storage != ikeAttemptOnly {
		result.storage = "unsupported"
		return result
	}
	a, _ := ctx.Value(ikeAuthorityKey{}).(*ikeAuth)
	if a == nil {
		return result
	}
	s.ikeMu.Lock()
	defer s.ikeMu.Unlock()
	if a.owner != s {
		return result
	}
	if !s.ikeLifecycleLocked(a, b) || s.ikePending != a || ctx.Err() != nil || a.owner != s || !a.live || a.consume == nil || !time.Now().Before(a.deadline) {
		s.retireIKEAuthLocked(a)
		return result
	}
	if b != a.binding || intent != ikePassword {
		return result
	}
	for _, v := range [][]byte{secrets.username, secrets.password} {
		if len(v) == 0 || len(v) > 1024 || !utf8.Valid(v) || bytes.ContainsRune(v, 0) {
			return result
		}
	}
	consume := a.consume
	s.retireIKEAuthLocked(a)
	consume(secrets.username, secrets.password)
	result.accepted = true
	return result
}

func (s *Server) disableIKEAuth() {
	s.ikeMu.Lock()
	defer s.ikeMu.Unlock()
	s.disableIKEAuthLocked()
}
func (s *Server) disableIKEAuthLocked() {
	s.ikeDisabled = true
	if s.ikePending != nil {
		s.retireIKEAuthLocked(s.ikePending)
	}
}
func (s *Server) ikeLifecycleLocked(a *ikeAuth, b ikeBinding) bool {
	if s.ikeOwner == nil || s.ikeOwner.Err() != nil {
		s.disableIKEAuthLocked()
	}
	if s.ikeDisabled || a.generation != s.ikeGeneration || s.ikeProfile == "" {
		return false
	}
	status := s.engine.Status()
	if s.ikePending != nil && (status.Session == nil || status.Session.ID != s.ikePending.binding.session || (status.State != core.Connecting && status.State != core.Connected)) {
		s.retireIKEAuthLocked(s.ikePending)
	}
	return status.Session != nil && status.Session.ID == b.session && (status.State == core.Connecting || status.State == core.Connected) && b.profile == s.ikeProfile && b.server == s.ikeServer && b.installation == s.installation && b.instance == s.instance
}
