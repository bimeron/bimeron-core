package core

import (
	"context"
	"errors"
	"sync"
	"time"

	"bimeron/internal/telemetry"
)

type State string

var ErrSessionRunning = errors.New("session already running")

const (
	Disconnected State = "disconnected"
	Connecting   State = "connecting"
	Connected    State = "connected"
	Reconnecting State = "reconnecting"
	Stopping     State = "stopping"
	Failed       State = "failed"
)

// Event contains only bounded diagnostic codes and messages, never destinations
// or credentials. Events may be dropped if the consumer is slow; Status is authoritative.
type Event struct {
	Time          time.Time
	State         State
	Code, Message string
	Attempt       int
	LastError     string
	ErrorStage    string `json:",omitempty"`
}
type Status struct {
	Native     *NativeStatus `json:"native,omitempty"`
	Session    *SessionInfo  `json:"Session,omitempty"`
	State      State
	Attempt    int
	Since      time.Time
	LastError  string
	ErrorStage string `json:",omitempty"`
}
type Options struct{ RetryMin, RetryMax time.Duration }

type session interface {
	Wait(context.Context) error
	Close() error
}
type persistentSession interface {
	Suspend()
	Reconnect(context.Context) error
}
type backend interface {
	Acquire(context.Context) (func(), error)
	Open(context.Context, SessionConfig, func(string, string)) (session, error)
}
type stageError struct {
	code  string
	retry bool
	stage string
}

func (e *stageError) Error() string       { return e.code }
func fault(code string, retry bool) error { return &stageError{code: code, retry: retry} }
func retryable(err error) bool            { var e *stageError; return errors.As(err, &e) && e.retry }

type Engine struct {
	mu         sync.Mutex
	opts       Options
	status     Status
	events     chan Event
	eventDrops uint64
	runResult  *runResult
	cancel     context.CancelFunc
	active     bool
	factory    func(SessionConfig) backend
	lastReport map[string]time.Time
	stats      *telemetry.Counters
}

// Stats returns counters for the most recent Start. Counters reset on every
// Start and remain readable after the session ends. Snapshots never contain
// addresses, credentials or destinations. Unavailable is set for native IKEv2
// sessions whose traffic does not pass through the core's packet counters.
func (e *Engine) Stats() telemetry.Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	snapshot := e.stats.Snapshot()
	snapshot.Unavailable = e.status.Session != nil && e.status.Session.StatsUnavailable
	return snapshot
}

type runResult struct {
	done chan struct{}
	err  error
}

func New(options Options) *Engine {
	if options.RetryMin <= 0 {
		options.RetryMin = time.Second
	}
	if options.RetryMax < options.RetryMin {
		options.RetryMax = 30 * time.Second
		if options.RetryMax < options.RetryMin {
			options.RetryMax = options.RetryMin
		}
	}
	return &Engine{opts: options, status: Status{State: Disconnected, Since: time.Now()}, events: make(chan Event, 128), factory: newBackend, lastReport: map[string]time.Time{}}
}
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	status := e.status
	if status.Native != nil {
		snapshot := *status.Native
		status.Native = &snapshot
	}
	if status.Session != nil {
		info := *status.Session
		info.Active = e.active
		status.Session = &info
	}
	return status
}

// Events is one stream for the lifetime of Engine. It is not closed between runs.
func (e *Engine) Events() <-chan Event { return e.events }

// EventDrops counts loss before the control history buffer.
func (e *Engine) EventDrops() uint64 { e.mu.Lock(); defer e.mu.Unlock(); return e.eventDrops }
func (e *Engine) emitLocked(code, message string) {
	select {
	case e.events <- Event{Time: time.Now(), State: e.status.State, Code: code, Message: message, Attempt: e.status.Attempt, LastError: e.status.LastError, ErrorStage: e.status.ErrorStage}:
	default:
		e.eventDrops++
	}
}
func (e *Engine) transition(state State, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.transitionLocked(state, err)
}
func (e *Engine) transitionLocked(state State, err error) {
	// Stop wins a race with successful startup or a failed health probe.
	if e.status.State == Stopping && (state == Connected || state == Reconnecting) {
		return
	}
	if e.status.State == state && (err == nil || e.status.LastError == err.Error()) {
		return
	}
	e.status.State = state
	e.status.Since = time.Now()
	if err != nil {
		e.status.LastError = err.Error()
		var staged *stageError
		if errors.As(err, &staged) {
			e.status.ErrorStage = staged.stage
		} else {
			e.status.ErrorStage = ""
		}
	} else if state == Connected || state == Disconnected {
		e.status.LastError = ""
		e.status.ErrorStage = ""
	}
	e.emitLocked("state", string(state))
}
func (e *Engine) report(code, message string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if time.Since(e.lastReport[code]) < 5*time.Second {
		return
	}
	e.lastReport[code] = time.Now()
	e.emitLocked(code, message)
}

// Start validates synchronously and schedules connection. Connected is reported
// only after setup completes. The supplied context owns the entire session.
func (e *Engine) Start(ctx context.Context, cfg SessionConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if cfg.IKEv2 != nil {
		ike := *cfg.IKEv2
		cfg.IKEv2 = &ike
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := newSessionInfo(cfg)
	if err != nil {
		return err
	}
	cfg.DNS = append([]string(nil), cfg.DNS...)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.active {
		return ErrSessionRunning
	}
	e.stats = &telemetry.Counters{}
	cfg.stats = e.stats
	ctx, e.cancel = context.WithCancel(ctx)
	e.runResult = &runResult{done: make(chan struct{})}
	e.active = true
	e.status = Status{Session: info, State: Connecting, Since: time.Now()}
	if cfg.IKEv2 != nil {
		e.status.Native = &NativeStatus{ProfileReadiness: "not_checked", CredentialReadiness: "not_checked", CertificateReadiness: "not_checked", Requested: cfg.IKEv2.KillSwitch, WFP: "inactive", DNS: "inactive", RASCleanup: "not_started", DNSCleanup: "not_started", WFPCleanup: "not_started"}
		cfg.nativeUpdate = func(update func(*NativeStatus)) {
			e.mu.Lock()
			defer e.mu.Unlock()
			update(e.status.Native)
		}
	}
	e.lastReport = map[string]time.Time{}
	e.emitLocked("state", string(Connecting))
	go e.run(ctx, cfg, e.runResult)
	return nil
}

// Stop is idempotent. A caller timeout ends only its wait: cleanup continues in
// the background, and another Start remains forbidden until it has finished.
func (e *Engine) Stop(ctx context.Context) error {
	e.mu.Lock()
	if e.active {
		e.cancel()
		if e.status.State != Stopping {
			e.status.State = Stopping
			e.status.Since = time.Now()
			e.emitLocked("state", string(Stopping))
		}
	}
	r := e.runResult
	e.mu.Unlock()
	if r == nil {
		return nil
	}
	select {
	case <-r.done:
		return r.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (e *Engine) Wait(ctx context.Context) error {
	e.mu.Lock()
	r := e.runResult
	e.mu.Unlock()
	if r == nil {
		return nil
	}
	select {
	case <-r.done:
		return r.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) run(ctx context.Context, cfg SessionConfig, r *runResult) {
	cfg.endpointChanged = func(endpoints sessionEndpoints) {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.status.Session != nil {
			e.status.Session.ServerTCP = endpoints.tcp
			e.status.Session.ServerUDP = endpoints.udp
			e.status.Session.ServerTCPName = endpoints.tcpName
			e.status.Session.ServerUDPName = endpoints.udpName
		}
	}
	var result error
	defer func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if result != nil {
			e.transitionLocked(Failed, result)
		} else {
			e.transitionLocked(Disconnected, nil)
		}
		r.err = result
		e.active = false
		e.cancel()
		close(r.done)
	}()
	b := e.factory(cfg)
	release, err := b.Acquire(ctx)
	if err != nil {
		if cfg.IKEv2 != nil && err.Error() == "ikev2_existing_kill_switch_requires_recovery" {
			cfg.updateNative(func(n *NativeStatus) { n.WFP = "unknown"; n.DNS = "unknown"; n.RecoveryRequired = true })
		}
		if ctx.Err() == nil {
			result = err
		}
		return
	}
	defer release() // includes OS-thread-owned session lock; runs on this goroutine.
	delay := e.opts.RetryMin
	for {
		if ctx.Err() != nil {
			return
		}
		e.mu.Lock()
		e.status.Attempt++
		e.mu.Unlock()
		s, err := b.Open(ctx, cfg, e.report)
		if err == nil {
			if ctx.Err() == nil {
				e.transition(Connected, nil)
			}
			connectedAt := time.Now()
			err = e.serve(ctx, s)
			if ctx.Err() != nil {
				e.transition(Stopping, nil)
			} else if retryable(err) {
				e.transition(Reconnecting, err)
			}
			if closeErr := s.Close(); closeErr != nil {
				result = closeErr
				return
			}
			if time.Since(connectedAt) >= time.Minute {
				delay = e.opts.RetryMin
			}
		}
		// Open owns rollback on failure. A cleanup failure must stay visible even
		// when cancellation arrived at the same time.
		if err != nil && !retryable(err) && !errors.Is(err, context.Canceled) {
			result = err
			return
		}
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			result = fault("session_stopped_unexpectedly", false)
			return
		}
		e.transition(Reconnecting, err)
		e.report("retry", "Connection interrupted; retrying after cleanup")
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if delay < e.opts.RetryMax/2 {
			delay *= 2
		} else {
			delay = e.opts.RetryMax
		}
	}
}

// A persistent VPN session keeps its link while replacing transport generations.
// Ordinary backends retain the previous close-and-open retry behavior.
func (e *Engine) serve(ctx context.Context, s session) error {
	p, ok := s.(persistentSession)
	if !ok {
		return s.Wait(ctx)
	}
	delay := e.opts.RetryMin
	for {
		connectedAt := time.Now()
		err := s.Wait(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !retryable(err) {
			return err
		}
		if time.Since(connectedAt) >= time.Minute {
			delay = e.opts.RetryMin
		}
		e.transition(Reconnecting, err)
		p.Suspend()
		e.report("transport_suspend", "Tunnel retained; proxy traffic blocked during recovery")
		for {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			e.mu.Lock()
			e.status.Attempt++
			e.mu.Unlock()
			err = p.Reconnect(ctx)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err == nil {
				e.transition(Connected, nil)
				break
			}
			if !retryable(err) {
				return err
			}
			e.transition(Reconnecting, err)
			e.report("transport_retry", "Transport unavailable; tunnel remains installed")
			if delay < e.opts.RetryMax/2 {
				delay *= 2
			} else {
				delay = e.opts.RetryMax
			}
		}
	}
}
