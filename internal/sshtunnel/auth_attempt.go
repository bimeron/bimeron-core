package sshtunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// attempt keeps one cumulative network budget; local interaction never extends
// the caller's deadline. All timer transitions are serialized with cancellation.
// promptTimeout bounds each local prompt, including host-key offers.
var promptTimeout = 60 * time.Second

type attempt struct {
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	timer     *time.Timer
	remaining time.Duration
	started   time.Time
	rounds    int
}

func newAttempt(ctx context.Context) *attempt {
	ctx, cancel := context.WithCancel(ctx)
	return &attempt{ctx: ctx, cancel: cancel, remaining: 20 * time.Second}
}
func (a *attempt) resume() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ctx.Err() != nil {
		return
	}
	a.started = time.Now()
	a.timer = time.AfterFunc(a.remaining, a.cancel)
}
func (a *attempt) prompt(p Prompt) Prompt {
	return func(_ context.Context, c Challenge) ([]string, error) {
		a.mu.Lock()
		if a.ctx.Err() != nil || a.rounds >= 8 {
			a.mu.Unlock()
			a.cancel()
			return nil, errors.New("SSH authentication unavailable")
		}
		a.rounds++
		active := a.timer != nil
		if active {
			if !a.timer.Stop() {
				a.mu.Unlock()
				a.cancel()
				return nil, errors.New("SSH authentication unavailable")
			}
			a.remaining -= time.Since(a.started)
			a.timer = nil
		}
		a.mu.Unlock()
		ctx, cancel := context.WithTimeout(a.ctx, promptTimeout)
		answers, err := p(ctx, c)
		if ctx.Err() != nil {
			err = errors.New("SSH authentication unavailable")
		}
		cancel()
		if err != nil {
			a.cancel()
			if errors.Is(err, ErrHostKeyDeclined) {
				return nil, ErrHostKeyDeclined
			}
			return nil, errors.New("SSH authentication unavailable")
		}
		if active {
			a.resume()
		}
		return answers, nil
	}
}
func (a *attempt) close() {
	a.cancel()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.timer != nil {
		a.timer.Stop()
	}
}

type attemptConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (c attemptConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if e != nil {
		c.cancel()
	}
	return n, e
}
func (c attemptConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	if e != nil {
		c.cancel()
	}
	return n, e
}
