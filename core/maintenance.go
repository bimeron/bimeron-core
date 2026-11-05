package core

import (
	"context"
	"errors"
	"sync"
)

var (
	errMaintenanceSealed   = errors.New("maintenance_pending")
	errMaintenanceConflict = errors.New("operation_conflict")
	errMaintenanceStorage  = errors.New("storage_failed")
	errMaintenanceTarget   = errors.New("stale_session")
	errMaintenanceUnknown  = errors.New("recovery_required")
	errMaintenanceFull     = errors.New("history_full")
)

// These types are internal test seams, not a production schema or authority check.
// Empty Session means explicitly idle; active targets carry the Engine session ID.
type maintenanceIdentity struct {
	Installation, Boot, Instance string
}
type maintenanceRequest struct {
	Identity                       maintenanceIdentity
	Operation, Request, GateDigest string
	Generation, Sequence           uint64
	Session                        string
}
type maintenanceOutcome string

const (
	maintenancePending       maintenanceOutcome = "cleanup_pending"
	maintenanceRecovery      maintenanceOutcome = "recovery_required"
	maintenanceFailed        maintenanceOutcome = "cleanup_failed"
	maintenanceStorageFailed maintenanceOutcome = "storage_failed"
)

type maintenanceResult struct {
	Request                                maintenanceRequest
	Outcome                                maintenanceOutcome
	StopCompleted, Inactive, CleanupFailed bool
}
type maintenanceStatus struct {
	Sealed bool
	Result maintenanceResult
	Known  bool
}

// The owner publishes the gate before Shutdown. Core never writes the gate.
// Implementations must return detached values and must not call coordinator mutations.
// No production adapter or durability guarantee is provided by this interface.
type maintenanceStore interface {
	ReadGate() (maintenanceRequest, error)
	WriteResult(maintenanceResult) error
}
type maintenanceCoordinator struct {
	admission sync.Mutex
	mu        sync.Mutex
	engine    *Engine
	store     maintenanceStore
	identity  maintenanceIdentity
	result    maintenanceResult
	done      chan struct{}
}

func newMaintenanceCoordinator(e *Engine, store maintenanceStore, identity maintenanceIdentity) (*maintenanceCoordinator, error) {
	if e == nil || store == nil || !boundedMaintenance(identity.Installation) || !boundedMaintenance(identity.Boot) || !boundedMaintenance(identity.Instance) {
		return nil, errMaintenanceUnknown
	}
	c := &maintenanceCoordinator{engine: e, store: store, identity: identity}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.maintenance != nil {
		return nil, errMaintenanceConflict
	}
	e.maintenance = c // Attachment is sealed before this constructor returns.
	return c, nil
}
func boundedMaintenance(s string) bool { return len(s) > 0 && len(s) <= 128 }
func (c *maintenanceCoordinator) Status() maintenanceStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return maintenanceStatus{Sealed: true, Result: c.result, Known: c.done != nil}
}
func (c *maintenanceCoordinator) Query(request maintenanceRequest) (maintenanceResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done == nil {
		return maintenanceResult{}, errMaintenanceUnknown
	}
	if c.result.Request != request {
		if c.result.Request.Operation == request.Operation || c.result.Request.Request == request.Request {
			return maintenanceResult{}, errMaintenanceConflict
		}
		return maintenanceResult{}, errMaintenanceUnknown
	}
	return c.result, nil
}
func (c *maintenanceCoordinator) Shutdown(ctx context.Context, request maintenanceRequest) (maintenanceResult, error) {
	c.admission.Lock()
	done, err := c.admit(request)
	c.admission.Unlock()
	if err != nil {
		return maintenanceResult{}, err
	}
	select {
	case <-done:
		return c.Query(request)
	case <-ctx.Done():
		return maintenanceResult{}, ctx.Err()
	}
}
func (c *maintenanceCoordinator) admit(request maintenanceRequest) (<-chan struct{}, error) {
	c.mu.Lock()
	if c.done != nil {
		prior, done := c.result.Request, c.done
		c.mu.Unlock()
		if prior == request {
			return done, nil
		}
		if prior.Operation == request.Operation || prior.Request == request.Request {
			return nil, errMaintenanceConflict
		}
		return nil, errMaintenanceFull
	}
	c.mu.Unlock()
	if request.Identity != c.identity || !boundedMaintenance(request.Operation) || !boundedMaintenance(request.Request) || !boundedMaintenance(request.GateDigest) || len(request.Session) > 128 || request.Generation == 0 || request.Sequence == 0 {
		return nil, errMaintenanceUnknown
	}
	gate, err := c.store.ReadGate()
	if err != nil {
		return nil, errMaintenanceStorage
	}
	if gate != request {
		return nil, errMaintenanceConflict
	}
	c.engine.mu.Lock()
	session := ""
	if c.engine.active {
		session = c.engine.status.Session.ID
	}
	c.engine.mu.Unlock()
	if session != request.Session {
		return nil, errMaintenanceTarget
	}
	c.mu.Lock()
	c.result = maintenanceResult{Request: request, Outcome: maintenancePending}
	c.done = make(chan struct{})
	done := c.done
	c.mu.Unlock()
	go c.stop(request, done)
	return done, nil
}
func (c *maintenanceCoordinator) stop(request maintenanceRequest, done chan struct{}) {
	// The operation, not a transport waiter, owns cleanup and publication.
	err := c.engine.Stop(context.Background())
	status := c.engine.Status()
	result := maintenanceResult{Request: request, Outcome: maintenanceRecovery, StopCompleted: true, Inactive: status.Session == nil || !status.Session.Active}
	if err != nil {
		result.Outcome = maintenanceFailed
		result.CleanupFailed = true
	}
	if c.store.WriteResult(result) != nil {
		result.Outcome = maintenanceStorageFailed
	}
	c.mu.Lock()
	c.result = result
	close(done)
	c.mu.Unlock()
}

// Engine never takes command admission: entry checks only take its short mutex.
func (e *Engine) maintenanceBarrier() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.maintenance != nil {
		return errMaintenanceSealed
	}
	return nil
}
