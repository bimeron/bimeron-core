package core

import (
	"context"
	"errors"
	"sync"
	"time"

	"bimeron/internal/guard"
	"bimeron/internal/problem"
	"bimeron/internal/telemetry"
)

type State string

var errGuardedPanic = errors.New("guarded goroutine panicked")

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
	ReconnectAttempt   int       `json:",omitempty"`
	ReconnectLimit     int       `json:",omitempty"`
	ReconnectCycle     int       `json:",omitempty"`
	ReconnectPhase     string    `json:",omitempty"`
	NextAttemptAt      time.Time `json:",omitzero"`
	KillSwitch         string    `json:",omitempty"`
	Time               time.Time
	State              State
	Code, Message      string
	Attempt            int
	LastError          string
	ErrorStage         string `json:",omitempty"`
	LastErrorPermanent bool   `json:",omitempty"`
}
type Status struct {
	ReconnectAttempt int `json:",omitempty"`
	ReconnectLimit   int `json:",omitempty"`
	// ReconnectCycle is the current or most recent recovery cycle after loss
	// of an established session; omitted during initial connection attempts.
	ReconnectCycle int `json:",omitempty"`
	// ReconnectPhase is PhaseAttempting or PhaseWaiting while reconnecting.
	ReconnectPhase string `json:",omitempty"`
	// NextAttemptAt is the UTC time of the next scheduled attempt or cycle.
	NextAttemptAt time.Time `json:",omitzero"`
	// KillSwitch is KillSwitchActive or KillSwitchHolding while the run owns
	// kill switch protection; omitted otherwise.
	KillSwitch string `json:",omitempty"`
	// ResidualReason is ResidualUpdate when residual protection was kept on
	// purpose across a service update (ADR 0041); omitted otherwise.
	ResidualReason string `json:",omitempty"`
	// ResidualProfile is the profile_id of the session whose protection was
	// kept across the update; omitted otherwise.
	ResidualProfile string        `json:",omitempty"`
	Native          *NativeStatus `json:"native,omitempty"`
	Session         *SessionInfo  `json:"Session,omitempty"`
	State           State
	Attempt         int
	Since           time.Time
	LastError       string
	ErrorStage      string `json:",omitempty"`
	// LastErrorPermanent marks a LastError that retrying alone does not fix,
	// for example a rejected access key. It ends an initial connection at
	// once; after loss of an established session Core still retries it.
	LastErrorPermanent bool `json:",omitempty"`
}

// StatsSnapshot binds cumulative counters to a per-Start session.
// Status.Attempt provides retry context; counters are not per-attempt.
// Counters is nil until the first accepted Start.
type StatsSnapshot struct {
	Status   Status              `json:"status"`
	Counters *telemetry.Snapshot `json:"counters,omitempty"`
}

// Options tune retry timing. RetryMin and RetryMax bound the initial-connection
// backoff; RetryMin and CycleRetryMax bound the backoff inside a recovery
// cycle; CyclePause separates recovery cycles. Zero values select defaults.
//
// ResidualProtection makes an idle engine report kill switch protection that
// no run owns (Status.KillSwitch "residual"); daemons and services enable it.
// UpdateHold, when set, is the record of protection kept across a service
// update: residual protection then also reports the held profile, and a run
// that starts consumes the record (ADR 0041).
type Options struct {
	RetryMin, RetryMax, CycleRetryMax, CyclePause time.Duration
	ResidualProtection                            bool
	UpdateHold                                    *UpdateHold
}

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
	cause error // Only sanitized sentinels may be exposed to callers.
	code  string
	retry bool
	stage string
}

func (e *stageError) Unwrap() error       { return e.cause }
func (e *stageError) Error() string       { return e.code }
func fault(code string, retry bool) error { return &stageError{code: code, retry: retry} }
func retryable(err error) bool            { var e *stageError; return errors.As(err, &e) && e.retry }

// connectionFailed is the LastError code for failures that carry no catalog code.
const connectionFailed = "connection_failed"

// codeFault converts err from a platform or native component into a fault
// whose code is safe to show to users. A stageError with a catalog code is kept
// as is; otherwise err's text is used only when it is a catalog code, and any
// other text becomes fallback. fallback must be a catalog code.
func codeFault(err error, fallback string, retry bool) error {
	var staged *stageError
	if errors.As(err, &staged) && problem.Known(staged.code) {
		return staged
	}
	code := fallback
	if err != nil && problem.Known(err.Error()) {
		code = err.Error()
	}
	return fault(code, retry)
}

// lastErrorCode is the Status.LastError value for err. Clients show it to
// users, so text that is not a catalog code never reaches it.
func lastErrorCode(err error) string {
	if code := err.Error(); problem.Known(code) {
		return code
	}
	return connectionFailed
}

type Engine struct {
	// lifecycle serializes Start and the cancellation step of Stop, so a
	// kill switch handover cannot interleave with another session change.
	lifecycle sync.Mutex
	mu        sync.Mutex
	recovery  recovery
	wake      chan struct{}
	holding   bool // a failed run keeps kill switch protection until Stop
	protected bool // the run owns kill switch protection
	handover  bool // the held run exits for a new Start and keeps protection
	abandon   bool // the run exits without a user stop and keeps protection
	// stopRequested records Stop for the current run. The published state is
	// not evidence of it: a run entering the held failed state can publish
	// failed over stopping.
	stopRequested bool
	// exiting is set for good once the owner abandons the engine: no later
	// Start may install, and then release, protection.
	exiting   bool
	pollEvery time.Duration
	observe   func(tunnel string) string
	network   func() string
	// residual caches idle kill switch protection found by residualProbe.
	residual bool
	// residualProfile is the profile whose protection was kept across a
	// service update, while that protection is residual.
	residualProfile string
	residualChecked time.Time
	residualProbe   func() (bool, error)
	// installedProbe reports whether any Bimeron protection is installed,
	// owned or not; the update record is kept until it is gone.
	installedProbe func() (bool, error)
	// repanic rethrows a run panic after protection is retained; tests stub it.
	repanic     func(any)
	maintenance *maintenanceCoordinator
	opts        Options
	status      Status
	events      chan Event
	eventDrops  uint64
	runResult   *runResult
	cancel      context.CancelFunc
	active      bool
	factory     func(SessionConfig) backend
	lastReport  map[string]time.Time
	stats       *telemetry.Counters
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
	// acquired is closed once Acquire has returned or the run ended earlier.
	acquired chan struct{}
	err      error
	// settled marks a terminal session failure whose teardown already
	// completed. Wait still reports err; a later Stop has nothing left to clean.
	settled bool
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
	if options.CycleRetryMax <= 0 {
		options.CycleRetryMax = 15 * time.Second
	}
	options.CycleRetryMax = max(options.CycleRetryMax, options.RetryMin)
	if options.CyclePause <= 0 {
		options.CyclePause = time.Minute
	}
	return &Engine{opts: options, status: Status{State: Disconnected, Since: time.Now()}, events: make(chan Event, 128), factory: newBackend, lastReport: map[string]time.Time{}, pollEvery: 5 * time.Second, observe: interfaceIdentity, residualProbe: residualProtection, installedProbe: protectionInstalled, repanic: func(p any) { panic(p) }}
}

// StatsSnapshot returns detached session metadata and counters under one lock.
// Terminal sessions retain their counters, including native unavailability.
// Counter fields are independently sampled and need not form one atomic tuple.
func (e *Engine) StatsSnapshot() StatsSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	snapshot := StatsSnapshot{Status: e.statusLocked()}
	if snapshot.Status.Session != nil {
		counters := e.stats.Snapshot()
		counters.Unavailable = snapshot.Status.Session.StatsUnavailable
		snapshot.Counters = &counters
	}
	return snapshot
}

func (e *Engine) Status() Status {
	e.refreshResidual()
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.statusLocked()
}

func (e *Engine) statusLocked() Status {
	status := e.status
	if e.protected {
		status.KillSwitch = KillSwitchHolding
		if status.State == Connected {
			status.KillSwitch = KillSwitchActive
		}
	}
	e.residualStatusLocked(&status)
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
	case e.events <- e.eventLocked(code, message):
	default:
		e.eventDrops++
	}
}
func (e *Engine) eventLocked(code, message string) Event {
	s := e.statusLocked()
	return Event{Time: time.Now(), State: s.State, Code: code, Message: message, Attempt: s.Attempt, LastError: s.LastError, ErrorStage: s.ErrorStage, LastErrorPermanent: s.LastErrorPermanent,
		ReconnectAttempt: s.ReconnectAttempt, ReconnectLimit: s.ReconnectLimit, ReconnectCycle: s.ReconnectCycle, ReconnectPhase: s.ReconnectPhase, NextAttemptAt: s.NextAttemptAt, KillSwitch: s.KillSwitch}
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
	if e.status.State == state && (err == nil || e.status.LastError == lastErrorCode(err)) {
		return
	}
	e.status.State = state
	e.status.Since = time.Now()
	if err != nil {
		e.status.LastError = lastErrorCode(err)
		var staged *stageError
		if errors.As(err, &staged) {
			e.status.ErrorStage = staged.stage
		} else {
			e.status.ErrorStage = ""
		}
		e.status.LastErrorPermanent = staged != nil && !staged.retry
	} else if state == Connected || state == Disconnected {
		e.status.LastError = ""
		e.status.LastErrorPermanent = false
		e.status.ReconnectAttempt = 0
		e.status.ReconnectLimit = 0
		e.status.ReconnectCycle = 0
		e.status.ErrorStage = ""
	}
	if state != Reconnecting {
		e.status.ReconnectPhase = ""
		e.status.NextAttemptAt = time.Time{}
	}
	if state == Connected {
		e.connectedLocked()
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
//
// A failed run that still holds kill switch protection is replaced without
// releasing it when cfg keeps a kill switch; otherwise Start returns
// ErrKillSwitchHeld and an explicit Stop must release the protection first.
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
	e.lifecycle.Lock()
	defer e.lifecycle.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.maintenance != nil {
		return errMaintenanceSealed
	}
	// The owner may have failed while this Start waited for the lock.
	if e.exiting {
		return ErrEngineExiting
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	keepsProtection := cfg.KillSwitch && cfg.Mode == "vpn" && cfg.IKEv2 == nil
	if e.active && e.holding && !keepsProtection {
		return ErrKillSwitchHeld
	}
	// A repeated start of the running profile (for example a double click)
	// never interrupts a live session; a held failure may always be retried.
	switching := e.holding || !sameProfile(e.status.Session, info)
	// A stop in progress, for example after the caller's Stop timed out, is
	// never turned into a handover: Start waits until it has finished.
	if e.active && e.stopRequested {
		return ErrSessionRunning
	}
	if e.active && (e.holding || e.protected) && keepsProtection && switching {
		// Hand the installed protection over: the previous run closes its
		// session and releases its lock but keeps the persistent filters for
		// the next Acquire to replace, so switching profiles leaves no gap.
		e.handover = true
		e.cancel()
		previous := e.runResult
		e.mu.Unlock()
		<-previous.done // bounded by the previous session's cleanup
		e.mu.Lock()
		// The previous teardown left state behind: report it, never mask it,
		// even when the owner fails or the caller gives up meanwhile.
		failedCleanup := previous.err != nil && cleanupFailed(previous.err)
		if failedCleanup {
			e.status.Session = nil
			e.transitionLocked(Failed, previous.err)
		}
		// The previous run kept its filters for the handover; if the owner
		// failed or the caller gave up meanwhile, leave them installed
		// (residual), end the stopping state and start nothing.
		var refused error
		if e.exiting {
			refused = ErrEngineExiting
		} else {
			refused = ctx.Err()
		}
		if refused != nil {
			if !failedCleanup {
				e.status.Session = nil
				e.transitionLocked(Disconnected, nil)
			}
			return refused
		}
		if failedCleanup {
			return previous.err
		}
	}
	if e.active {
		return ErrSessionRunning
	}
	e.stats = &telemetry.Counters{}
	cfg.stats = e.stats
	ctx, e.cancel = context.WithCancel(ctx)
	e.runResult = &runResult{done: make(chan struct{}), acquired: make(chan struct{})}
	e.active = true
	e.holding, e.handover, e.protected, e.abandon, e.stopRequested = false, false, false, false, false
	e.residual = false // the run owns or replaces any earlier protection
	e.residualProfile = ""
	e.recovery = recovery{cycles: cfg.IKEv2 == nil}
	e.wake = make(chan struct{}, 1)
	observe, tunnel := e.observe, cfg.Name
	e.network = func() string { return observe(tunnel) }
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
	r := e.runResult
	go e.run(ctx, cfg, r)
	if cfg.KillSwitch {
		// Return only once the run has installed its protection (or failed
		// to), so an accepted Start never precedes the kill switch.
		e.mu.Unlock()
		<-r.acquired
		e.mu.Lock()
	}
	return nil
}

// Abandon ends the session like Stop but keeps kill switch protection
// installed, for exits that are not a user's stop, such as a failed control
// listener. The protection is then reported as residual until recover.
func (e *Engine) Abandon(ctx context.Context) error {
	e.MarkAbandon()
	return e.Stop(ctx)
}

// MarkAbandon makes the current run keep its protection however it ends. Call
// it before cancelling the context the session was started with.
//
// A user's stop already in progress is left to release protection, and no
// later Start is accepted.
func (e *Engine) MarkAbandon() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.markAbandonLocked()
}

// MarkUpdateAbandon waits for any acquiring or switching run, then records the
// owner while teardown is excluded. A failed record still retains protection.
func (e *Engine) MarkUpdateAbandon(record func(string) error) error {
	e.lifecycle.Lock()
	defer e.lifecycle.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.markAbandonLocked()
	if e.abandon && e.protected && !e.stopRequested {
		if record == nil {
			return errors.New("update hold record unavailable")
		}
		err := record(e.status.Session.ProfileID)
		if err != nil && e.opts.UpdateHold != nil {
			err = errors.Join(err, e.opts.UpdateHold.Clear())
		}
		return err
	}
	return nil
}

func (e *Engine) markAbandonLocked() {
	e.exiting = true
	userStop := e.stopRequested && !e.handover
	if e.active && !userStop {
		e.abandon = true
	}
}

// Stop is idempotent. A caller timeout ends only its wait: cleanup continues in
// the background, and another Start remains forbidden until it has finished.
// Stop is the only path that releases kill switch protection held by a run.
func (e *Engine) Stop(ctx context.Context) error {
	e.lifecycle.Lock()
	e.mu.Lock()
	if e.active {
		e.stopRequested = true
		e.cancel()
		if e.status.State != Stopping {
			e.status.State = Stopping
			e.status.Since = time.Now()
			e.emitLocked("state", string(Stopping))
		}
	}
	r := e.runResult
	e.mu.Unlock()
	e.lifecycle.Unlock()
	if r == nil {
		return nil
	}
	select {
	case <-r.done:
		// Stop reports its own teardown, not an earlier settled session failure;
		// daemon exit status is used as service cleanup evidence.
		if r.settled {
			return nil
		}
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

// protectionOwner is a backend that can own run-scoped kill switch protection.
type protectionOwner interface {
	Protected() bool
	RetainProtection()
	ReleaseError() error
}

// Guard dispatch can precede run registration. Serialize each native cleanup
// decision with MarkAbandon. Only the guard bookkeeping runs under mu.
func (e *Engine) configureNativeCleanup(cfg *SessionConfig, claimed, commit func() bool) {
	cfg.retainNativeProtection = func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.abandon || claimed()
	}
	cfg.commitNativeStop = func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		return !e.abandon && commit()
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
	release := func() {}
	var owner protectionOwner
	acquired := sync.OnceFunc(func() { close(r.acquired) })
	// A panic in a guarded Core goroutine (relays, DNS, transport loops) ends
	// the run through the same crash path as a panic on this goroutine.
	ctx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(nil)
	crash := make(chan any, 1)
	cleaned := make(chan struct{})
	finished := sync.OnceFunc(func() { close(cleaned) })
	crashClaimed, commitStop, unregister := guard.RegisterSession(func(p any) <-chan struct{} {
		select {
		case crash <- p:
		default:
		}
		cancelRun(errGuardedPanic)
		return cleaned
	})
	e.configureNativeCleanup(&cfg, crashClaimed, commitStop)
	// Runs after the handler below, so a second panic during crash cleanup
	// still waits for it.
	defer unregister()
	defer func() {
		acquired()
		p := recover()
		guarded := false
		if p == nil && !commitStop() {
			p = <-crash
			guarded = true
		}
		if p != nil {
			// A crash keeps persistent protection, as after process termination.
			if owner != nil {
				owner.RetainProtection()
			}
			release()
			finished()
			if !guarded {
				e.repanic(p)
			}
			// A guarded goroutine rethrows its own panic, with the original
			// stack, once cleaned is closed.
			return
		}
		defer finished()
		e.mu.Lock()
		handover := e.handover
		abandon := e.abandon
		e.protected = false // teardown has committed to its retention decision
		e.mu.Unlock()
		// Protection outlives the run only for a handover or a failed cleanup,
		// which needs explicit recovery; every other exit is an explicit stop.
		retained := owner != nil && (handover || abandon || cleanupFailed(result))
		if retained {
			owner.RetainProtection()
		}
		release() // includes OS-thread-owned session lock; runs on this goroutine.
		if owner != nil && !retained && owner.ReleaseError() != nil && result == nil {
			// Protection is still installed: the stop did not clean up.
			result = fault("cleanup_failed_run_recover", false)
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		e.protected, e.holding = false, false
		e.residualChecked = time.Time{} // inspect again once idle
		if handover {
			// The next Start publishes its own status.
		} else if result != nil {
			e.transitionLocked(Failed, result)
		} else {
			e.transitionLocked(Disconnected, nil)
		}
		r.err = result
		e.active = false
		e.cancel()
		close(r.done)
	}()
	if err := e.maintenanceBarrier(); err != nil {
		result = err
		return
	}
	b := e.factory(cfg)
	if err := e.maintenanceBarrier(); err != nil {
		result = err
		return
	}
	releaseRun, err := b.Acquire(ctx)
	if err != nil {
		if cfg.IKEv2 != nil && err.Error() == "ikev2_existing_kill_switch_requires_recovery" {
			cfg.updateNative(func(n *NativeStatus) { n.WFP = "unknown"; n.DNS = "unknown"; n.RecoveryRequired = true })
		}
		if ctx.Err() == nil {
			result = err
		}
		return
	}
	release = releaseRun
	if o, ok := b.(protectionOwner); ok && o.Protected() {
		owner = o
		// This run's protection replaced any kept across an update.
		if hold := e.opts.UpdateHold; hold != nil {
			_ = hold.Clear()
		}
		e.mu.Lock()
		e.protected = true
		e.emitLocked("kill_switch_holding", "Kill switch active; traffic outside the tunnel is blocked until connection or stop")
		e.mu.Unlock()
	}
	acquired()
	for {
		err, settled := e.connect(ctx, cfg, b)
		// A cleanup failure stays visible even when Stop arrived at the same time.
		if err == nil || ctx.Err() != nil && !requiresRecovery(err) {
			return
		}
		// Without held protection, or when cleanup needs recovery, the failure
		// ends the run. Otherwise protection stays until Stop or a retry.
		if owner == nil || requiresRecovery(err) {
			result, r.settled = err, settled
			return
		}
		if !e.hold(ctx, err) {
			return
		}
	}
}

// hold keeps a failed run, and its kill switch protection, alive until Stop,
// a handover to a new Start, or ReconnectNow. It reports whether to retry.
func (e *Engine) hold(ctx context.Context, err error) bool {
	e.mu.Lock()
	// Stop or a handover cancels under mu: never publish failed over it.
	if ctx.Err() != nil {
		e.mu.Unlock()
		return false
	}
	e.transitionLocked(Failed, err)
	drain(e.wake)
	e.holding = true
	e.emitLocked("kill_switch_held", "Connection failed; kill switch keeps traffic blocked until stop")
	wake := e.wake
	e.mu.Unlock()
	select {
	case <-ctx.Done():
		return false
	case <-wake:
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil {
		return false
	}
	e.holding = false
	e.recovery = recovery{cycles: e.recovery.cycles}
	e.status.ReconnectAttempt, e.status.ReconnectLimit, e.status.ReconnectCycle = 0, 0, 0
	e.transitionLocked(Connecting, nil)
	e.emitLocked("reconnect_requested", "Reconnect requested; restarting connection attempts")
	return true
}

// connect runs attempts until Stop or a terminal failure. It returns nil after
// Stop, otherwise the failure; settled marks a failure whose teardown already
// completed.
func (e *Engine) connect(ctx context.Context, cfg SessionConfig, b backend) (error, bool) {
	for {
		if ctx.Err() != nil {
			return nil, false
		}
		e.mu.Lock()
		e.status.Attempt++
		e.mu.Unlock()
		if err := e.maintenanceBarrier(); err != nil {
			return err, false
		}
		s, err := b.Open(ctx, cfg, e.report)
		if err != nil && ctx.Err() == nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			// The setup deadline expired while the run continues: retry.
			err = fault("network_setup_failed", true)
		}
		if err == nil {
			if ctx.Err() == nil {
				e.transition(Connected, nil)
			}
			err = e.serve(ctx, s)
			if err == nil && ctx.Err() == nil {
				err = fault("session_stopped_unexpectedly", false)
			}
			if ctx.Err() != nil {
				e.transition(Stopping, nil)
			} else if e.recoverable(err) {
				e.transition(Reconnecting, err)
			}
			if closeErr := s.Close(); closeErr != nil {
				return closeFailure{closeErr}, false
			}
		}
		// Open owns rollback on failure. A cleanup failure must stay visible even
		// when cancellation arrived at the same time.
		if requiresRecovery(err) {
			return err, false
		}
		if ctx.Err() != nil {
			return nil, false
		}
		if !e.recoverable(err) {
			// Teardown of an unexpectedly stopped session has already completed.
			return err, err != nil && err.Error() == "session_stopped_unexpectedly"
		}
		e.report("retry", "Connection interrupted; retrying after cleanup")
		if waitErr := e.awaitAttempt(ctx, err); waitErr != nil {
			if ctx.Err() != nil {
				return nil, false
			}
			// Exhaustion follows a successful Close or Open rollback.
			return err, true
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
	for {
		err := s.Wait(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !retryable(err) {
			return err
		}
		p.Suspend()
		e.report("transport_suspend", "Tunnel retained; proxy traffic blocked during recovery")
		for {
			if waitErr := e.awaitAttempt(ctx, err); waitErr != nil {
				return waitErr
			}
			e.mu.Lock()
			e.status.Attempt++
			e.mu.Unlock()
			if err := e.maintenanceBarrier(); err != nil {
				return err
			}
			err = p.Reconnect(ctx)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				// The attempt deadline expired while the run continues: retry.
				err = fault("transport_unavailable", true)
			}
			if err == nil {
				e.transition(Connected, nil)
				break
			}
			// Failures of the tunnel itself are recovered by close and reopen.
			if !e.recoverable(err) || linkFault(err) {
				return err
			}
			e.transition(Reconnecting, err)
			e.report("transport_retry", "Transport unavailable; tunnel remains installed")
		}
	}
}
