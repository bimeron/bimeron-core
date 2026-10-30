package nativeenrollment

import "errors"

// These disconnected evidence types do not authenticate their inputs. A future
// transport must independently obtain peer PID/creation and pin the held image.
// No result grants admission, starts a process, or settles an operation.
type UpdateImage struct {
	Volume        uint64
	File          [16]byte
	Digest        [32]byte
	Role, Version string
	Protocol      uint32
}
type ServiceState uint8

const (
	ServiceRunning ServiceState = iota + 1
	ServiceStopped
)

type UpdateOperation struct {
	Pending             Record
	Candidate, Rollback UpdateImage
	Original            ServiceState
}
type ProcessIdentity struct {
	PID     uint32
	Created uint64
}
type HealthRequest struct {
	Operation UpdateOperation
	Challenge [32]byte
	Process   ProcessIdentity
}

// Peer is the OS-authenticated channel peer, HeldProcess the independently
// inspected process owning HeldImage. Response fields are not image authority.
type HealthEvidence struct {
	Binding           Record
	Challenge         [32]byte
	Peer, HeldProcess ProcessIdentity
	HeldImage         UpdateImage
	Role, Version     string
	Protocol          uint32
}

var errUpdateEvidence = errors.New("incomplete or conflicting offline update evidence")

func validUpdateImage(i UpdateImage) bool {
	return i.Volume != 0 && i.File != [16]byte{} && i.Digest != [32]byte{} && i.Role != "" && i.Version != "" && i.Protocol != 0
}
func validUpdateOperation(o UpdateOperation) bool {
	return valid(o.Pending) && o.Pending.Phase == Pending && validUpdateImage(o.Candidate) && validUpdateImage(o.Rollback) && (o.Candidate.Volume != o.Rollback.Volume || o.Candidate.File != o.Rollback.File) && (o.Original == ServiceRunning || o.Original == ServiceStopped)
}

// CheckUpdateHealth compares evidence only. Freshness requires a newly generated,
// single-use challenge supplied by a future authenticated transport; this pure
// function cannot detect resubmission of identical inputs or validate OS handles.
func CheckUpdateHealth(r HealthRequest, e HealthEvidence) error {
	if !validUpdateOperation(r.Operation) || r.Operation.Original != ServiceRunning || r.Challenge == [32]byte{} || r.Process.PID == 0 || r.Process.Created == 0 || e.Binding != r.Operation.Pending || e.Challenge != r.Challenge || e.Peer != r.Process || e.HeldProcess != r.Process || e.HeldImage != r.Operation.Candidate || e.Role != r.Operation.Candidate.Role || e.Version != r.Operation.Candidate.Version || e.Protocol != r.Operation.Candidate.Protocol {
		return errUpdateEvidence
	}
	return nil
}

type InventoryScope uint8

const CompleteInventory InventoryScope = 1

type UpdateInventory struct {
	Runnable, Rollback           []UpdateImage
	RunnableScope, RollbackScope InventoryScope
}

// CheckUpdateInventory requires complete exact approved sets. It cannot enforce
// inventory completeness or prevent later incompatible executable restoration.
func CheckUpdateInventory(o UpdateOperation, s UpdateInventory) error {
	if !validUpdateOperation(o) || s.RunnableScope != CompleteInventory || s.RollbackScope != CompleteInventory || len(s.Runnable) == 0 || len(s.Rollback) == 0 {
		return errUpdateEvidence
	}
	for _, i := range s.Runnable {
		if i != o.Candidate {
			return errUpdateEvidence
		}
	}
	for _, i := range s.Rollback {
		if i != o.Rollback {
			return errUpdateEvidence
		}
	}
	return nil
}

type UpdateOutcome uint8

const (
	ExecutionUnknown UpdateOutcome = iota
	CandidateHealthy
	CandidateInstalledStopped
	RestoredRunningSCMOnly
	RestoredStopped
	RollbackBlocked
)

// ObserveUpdateOutcome records a classification without asserting health or
// completion. RestoredRunningSCMOnly explicitly supplies no restored IPC proof.
func ObserveUpdateOutcome(o UpdateOperation, outcome UpdateOutcome) (Record, error) {
	if !validUpdateOperation(o) {
		return Record{}, errUpdateEvidence
	}
	switch outcome {
	case ExecutionUnknown, RollbackBlocked:
	case CandidateHealthy, RestoredRunningSCMOnly:
		if o.Original != ServiceRunning {
			return Record{}, errUpdateEvidence
		}
	case CandidateInstalledStopped, RestoredStopped:
		if o.Original != ServiceStopped {
			return Record{}, errUpdateEvidence
		}
	default:
		return Record{}, errUpdateEvidence
	}
	return o.Pending, nil
}
