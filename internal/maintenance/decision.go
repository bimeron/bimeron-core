// Package maintenance models offline maintenance eligibility. A Decision is
// eligibility for a later atomic recheck and reservation, never an OS
// permission, token or grant. No production code calls it yet. Native-enrolled
// baselines are always refused until durable recovery retention and lock
// continuation are accepted.
package maintenance

import "errors"

// Every enumeration's zero value is Unknown: access-denied, stale or missing
// evidence must be reported as Unknown, so partial Inputs are never eligible.
type (
	Operation uint8
	Baseline  uint8
	Pair      uint8
	Lifecycle uint8
	Cleanup   uint8
	Journal   uint8
	Lock      uint8
	Backup    uint8
	Retention uint8
)

const (
	OperationUnknown Operation = iota
	OperationServiceUpdate
	OperationServiceInstallOverExisting
	OperationServiceUninstall
	OperationServiceReconfigure
	OperationPackageMaintenance
)

const (
	BaselineUnknown    Baseline = iota
	BaselinePacketOnly          // agreed never-enrolled classification
	BaselineNativeEnrolled
)

const (
	PairUnknown Pair = iota
	PairExact
	PairMismatch
)

// LifecycleNativeActive covers any native session or still-open terminal
// foreground owner.
const (
	LifecycleUnknown Lifecycle = iota
	LifecycleIdle
	LifecyclePacketStarting
	LifecyclePacketActive
	LifecyclePacketStopping
	LifecycleNativeActive
	LifecycleProvisioning
	LifecycleMaintenanceInProgress
)

const (
	CleanupUnknown Cleanup = iota
	CleanupVerified
	CleanupPending
	CleanupFailed
)

const (
	JournalUnknown Journal = iota
	JournalClean
	JournalIncomplete
)

const (
	LockUnknown Lock = iota
	LockFree
	LockBusy
	LockAbandoned
)

const (
	BackupUnknown Backup = iota
	BackupNone
	BackupUnresolved
)

const (
	RetentionUnknown Retention = iota
	RetentionSufficient
	RetentionInsufficient
)

type Inputs struct {
	Operation Operation
	Baseline  Baseline
	Pair      Pair
	Lifecycle Lifecycle
	Cleanup   Cleanup
	Journal   Journal
	Lock      Lock
	Backup    Backup
	Retention Retention
}

// Verdict's zero value is RecoveryRequired, so a zero Decision never means
// Eligible.
type Verdict uint8

const (
	RecoveryRequired Verdict = iota
	Blocked
	RetryLater
	StopThenRetry
	Eligible
)

type Reason uint8

const (
	ReasonInvalidInput Reason = iota
	ReasonBaselineUnknown
	ReasonLifecycleUnknown
	ReasonCleanupUnknown
	ReasonJournalUnknown
	ReasonLockUnknown
	ReasonBackupUnknown
	ReasonCleanupFailed
	ReasonJournalIncomplete
	ReasonLockAbandoned
	ReasonBackupUnresolved
	ReasonInconsistentEvidence
	ReasonPairUnknown
	ReasonPairMismatch
	ReasonNativeMaintenanceBlocked
	ReasonRetentionUnknown
	ReasonRetentionInsufficient
	ReasonLockBusy
	ReasonCleanupPending
	ReasonLifecycleTransition
	ReasonPacketSessionActive
	ReasonEligible
)

type Decision struct {
	Verdict Verdict
	Reason  Reason
}

var ErrInvalidInput = errors.New("maintenance input outside its defined range")

func valid(in Inputs) bool {
	return in.Operation != OperationUnknown && in.Operation <= OperationPackageMaintenance &&
		in.Baseline <= BaselineNativeEnrolled && in.Pair <= PairMismatch &&
		in.Lifecycle <= LifecycleMaintenanceInProgress && in.Cleanup <= CleanupFailed &&
		in.Journal <= JournalIncomplete && in.Lock <= LockAbandoned &&
		in.Backup <= BackupUnresolved && in.Retention <= RetentionInsufficient
}

// Decide applies the fixed rule order; the first matching rule wins. All
// operations share one policy; operation-specific prerequisites stay with
// their commands.
func Decide(in Inputs) (Decision, error) {
	if !valid(in) {
		return Decision{RecoveryRequired, ReasonInvalidInput}, ErrInvalidInput
	}
	d := func(v Verdict, r Reason) (Decision, error) { return Decision{v, r}, nil }
	switch {
	case in.Baseline == BaselineUnknown:
		return d(RecoveryRequired, ReasonBaselineUnknown)
	case in.Lifecycle == LifecycleUnknown:
		return d(RecoveryRequired, ReasonLifecycleUnknown)
	case in.Cleanup == CleanupUnknown:
		return d(RecoveryRequired, ReasonCleanupUnknown)
	case in.Journal == JournalUnknown:
		return d(RecoveryRequired, ReasonJournalUnknown)
	case in.Lock == LockUnknown:
		return d(RecoveryRequired, ReasonLockUnknown)
	case in.Backup == BackupUnknown:
		return d(RecoveryRequired, ReasonBackupUnknown)
	case in.Cleanup == CleanupFailed:
		return d(RecoveryRequired, ReasonCleanupFailed)
	case in.Journal == JournalIncomplete:
		return d(RecoveryRequired, ReasonJournalIncomplete)
	case in.Lock == LockAbandoned:
		return d(RecoveryRequired, ReasonLockAbandoned)
	case in.Backup == BackupUnresolved:
		return d(RecoveryRequired, ReasonBackupUnresolved)
	case in.Baseline == BaselinePacketOnly && in.Lifecycle == LifecycleNativeActive:
		return d(RecoveryRequired, ReasonInconsistentEvidence)
	case in.Pair == PairUnknown:
		return d(Blocked, ReasonPairUnknown)
	case in.Pair == PairMismatch:
		return d(Blocked, ReasonPairMismatch)
	case in.Baseline == BaselineNativeEnrolled:
		return d(Blocked, ReasonNativeMaintenanceBlocked)
	case in.Retention == RetentionUnknown:
		return d(Blocked, ReasonRetentionUnknown)
	case in.Retention == RetentionInsufficient:
		return d(Blocked, ReasonRetentionInsufficient)
	case in.Lock == LockBusy:
		return d(RetryLater, ReasonLockBusy)
	case in.Cleanup == CleanupPending:
		return d(RetryLater, ReasonCleanupPending)
	case in.Lifecycle == LifecyclePacketStopping || in.Lifecycle == LifecycleProvisioning ||
		in.Lifecycle == LifecycleMaintenanceInProgress:
		return d(RetryLater, ReasonLifecycleTransition)
	case in.Lifecycle == LifecyclePacketStarting || in.Lifecycle == LifecyclePacketActive:
		return d(StopThenRetry, ReasonPacketSessionActive)
	}
	return d(Eligible, ReasonEligible)
}
