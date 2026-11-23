package core

import (
	"context"
	"runtime"
	"time"

	"bimeron/internal/guard"
)

const captivePortalEnabled = runtime.GOOS == "windows"
const captivePortalHint = "captive_portal"

type captivePortalState struct {
	local    string
	path     string
	reported bool
}

// beginPortalAttempt binds evidence to both the inspected outbound path and
// the local interface snapshot used by recovery.
func (e *Engine) beginPortalAttempt(path string) func() {
	e.mu.Lock()
	local := e.network()
	e.observePortalNetworkLocked(local)
	if e.portal == nil || e.portal.path != path {
		e.portal = &captivePortalState{local: local, path: path}
		e.clearPortalHintLocked()
	}
	network := e.portal
	e.mu.Unlock()
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.observePortalNetworkLocked(e.network())
		if e.portal != network || !e.protected || e.stopRequested {
			return
		}
		e.status.NetworkHint = captivePortalHint
		if !network.reported {
			network.reported = true
			e.emitLocked("captive_portal_suspected", "This network may require browser sign-in")
		}
	}
}

func (e *Engine) observePortalNetwork() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.portal != nil {
		e.observePortalNetworkLocked(e.network())
	}
}

func (e *Engine) observePortalNetworkLocked(local string) {
	if e.portal != nil && e.portal.local != local {
		e.portal = nil
		e.clearPortalHintLocked()
	}
}

func (e *Engine) clearPortalHintLocked() {
	if e.status.NetworkHint != "" {
		e.status.NetworkHint = ""
		e.emitLocked("state", string(e.status.State))
	}
}

// Watch the existing local interface snapshot even during a handshake or held
// failure. This reads host state without generating traffic or waking recovery.
func (e *Engine) watchPortalNetwork(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	guard.Go(func() {
		defer close(done)
		ticker := time.NewTicker(e.pollEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.observePortalNetwork()
			}
		}
	})
	return func() {
		cancel()
		<-done
	}
}
