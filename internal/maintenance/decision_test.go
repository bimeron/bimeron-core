package maintenance

import (
	"errors"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// Valid-range sizes including Unknown; kept literal so the tests do not trust
// the implementation's range checks.
const (
	nOperation = 6
	nBaseline  = 3
	nPair      = 3
	nLifecycle = 8
	nCleanup   = 4
	nJournal   = 3
	nLock      = 4
	nBackup    = 3
	nRetention = 3
)

var eligible = Inputs{
	Operation: OperationServiceUpdate,
	Baseline:  BaselinePacketOnly,
	Pair:      PairExact,
	Lifecycle: LifecycleIdle,
	Cleanup:   CleanupVerified,
	Journal:   JournalClean,
	Lock:      LockFree,
	Backup:    BackupNone,
	Retention: RetentionSufficient,
}

type rule struct {
	match   func(Inputs) bool
	verdict Verdict
	reason  Reason
}

// oracleRules restates the specification's ordered rules 2-6 as data,
// independently of Decide's control flow.
var oracleRules = []rule{
	{func(i Inputs) bool { return i.Baseline == 0 }, RecoveryRequired, ReasonBaselineUnknown},
	{func(i Inputs) bool { return i.Lifecycle == 0 }, RecoveryRequired, ReasonLifecycleUnknown},
	{func(i Inputs) bool { return i.Cleanup == 0 }, RecoveryRequired, ReasonCleanupUnknown},
	{func(i Inputs) bool { return i.Journal == 0 }, RecoveryRequired, ReasonJournalUnknown},
	{func(i Inputs) bool { return i.Lock == 0 }, RecoveryRequired, ReasonLockUnknown},
	{func(i Inputs) bool { return i.Backup == 0 }, RecoveryRequired, ReasonBackupUnknown},
	{func(i Inputs) bool { return i.Cleanup == CleanupFailed }, RecoveryRequired, ReasonCleanupFailed},
	{func(i Inputs) bool { return i.Journal == JournalIncomplete }, RecoveryRequired, ReasonJournalIncomplete},
	{func(i Inputs) bool { return i.Lock == LockAbandoned }, RecoveryRequired, ReasonLockAbandoned},
	{func(i Inputs) bool { return i.Backup == BackupUnresolved }, RecoveryRequired, ReasonBackupUnresolved},
	{func(i Inputs) bool { return i.Baseline == BaselinePacketOnly && i.Lifecycle == LifecycleNativeActive }, RecoveryRequired, ReasonInconsistentEvidence},
	{func(i Inputs) bool { return i.Pair == 0 }, Blocked, ReasonPairUnknown},
	{func(i Inputs) bool { return i.Pair == PairMismatch }, Blocked, ReasonPairMismatch},
	{func(i Inputs) bool { return i.Baseline == BaselineNativeEnrolled }, Blocked, ReasonNativeMaintenanceBlocked},
	{func(i Inputs) bool { return i.Retention == 0 }, Blocked, ReasonRetentionUnknown},
	{func(i Inputs) bool { return i.Retention == RetentionInsufficient }, Blocked, ReasonRetentionInsufficient},
	{func(i Inputs) bool { return i.Lock == LockBusy }, RetryLater, ReasonLockBusy},
	{func(i Inputs) bool { return i.Cleanup == CleanupPending }, RetryLater, ReasonCleanupPending},
	{func(i Inputs) bool {
		l := i.Lifecycle
		return l == LifecyclePacketStopping || l == LifecycleProvisioning || l == LifecycleMaintenanceInProgress
	}, RetryLater, ReasonLifecycleTransition},
	{func(i Inputs) bool {
		return i.Lifecycle == LifecyclePacketStarting || i.Lifecycle == LifecyclePacketActive
	}, StopThenRetry, ReasonPacketSessionActive},
}

func oracle(i Inputs) (Decision, bool) {
	if i.Operation == 0 {
		return Decision{RecoveryRequired, ReasonInvalidInput}, false
	}
	for _, r := range oracleRules {
		if r.match(i) {
			return Decision{r.verdict, r.reason}, true
		}
	}
	return Decision{Eligible, ReasonEligible}, true
}

func forEachValid(f func(Inputs)) {
	for op := 0; op < nOperation; op++ {
		for b := 0; b < nBaseline; b++ {
			for p := 0; p < nPair; p++ {
				for l := 0; l < nLifecycle; l++ {
					for c := 0; c < nCleanup; c++ {
						for j := 0; j < nJournal; j++ {
							for k := 0; k < nLock; k++ {
								for u := 0; u < nBackup; u++ {
									for r := 0; r < nRetention; r++ {
										f(Inputs{Operation(op), Baseline(b), Pair(p), Lifecycle(l), Cleanup(c), Journal(j), Lock(k), Backup(u), Retention(r)})
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestExhaustiveMatchesOracle(t *testing.T) {
	eligibleByOp := map[Operation]int{}
	n := 0
	forEachValid(func(in Inputs) {
		n++
		got, err := Decide(in)
		again, err2 := Decide(in)
		if got != again || err != err2 {
			t.Fatalf("nondeterministic for %+v", in)
		}
		want, ok := oracle(in)
		if ok != (err == nil) || (!ok && !errors.Is(err, ErrInvalidInput)) {
			t.Fatalf("%+v: err %v, oracle valid %v", in, err, ok)
		}
		if got != want {
			t.Fatalf("%+v: got %+v, want %+v", in, got, want)
		}
		if got.Verdict == Eligible {
			if in != (Inputs{in.Operation, BaselinePacketOnly, PairExact, LifecycleIdle, CleanupVerified, JournalClean, LockFree, BackupNone, RetentionSufficient}) {
				t.Fatalf("unexpected eligible tuple %+v", in)
			}
			eligibleByOp[in.Operation]++
		}
		unknown := in.Baseline == 0 || in.Lifecycle == 0 || in.Cleanup == 0 || in.Journal == 0 || in.Lock == 0 || in.Backup == 0
		if err == nil && unknown && got.Verdict != RecoveryRequired {
			t.Fatalf("unknown evidence %+v yielded %+v", in, got)
		}
		if in.Baseline == BaselineNativeEnrolled && (got.Verdict == Eligible || got.Verdict == StopThenRetry || got.Verdict == RetryLater) {
			t.Fatalf("native baseline %+v yielded %+v", in, got)
		}
	})
	if n != nOperation*nBaseline*nPair*nLifecycle*nCleanup*nJournal*nLock*nBackup*nRetention {
		t.Fatalf("enumerated %d tuples", n)
	}
	for op := Operation(1); op < nOperation; op++ {
		if eligibleByOp[op] != 1 {
			t.Fatalf("operation %d has %d eligible tuples", op, eligibleByOp[op])
		}
	}
	if len(eligibleByOp) != nOperation-1 {
		t.Fatalf("eligible operations: %v", eligibleByOp)
	}
}

func TestSingleFieldPerturbation(t *testing.T) {
	for op := Operation(1); op < nOperation; op++ {
		base := eligible
		base.Operation = op
		if d, err := Decide(base); err != nil || d != (Decision{Eligible, ReasonEligible}) {
			t.Fatalf("op %d eligible tuple: %+v %v", op, d, err)
		}
		check := func(field string, in Inputs) {
			if in == base {
				return
			}
			if d, _ := Decide(in); d.Verdict == Eligible {
				t.Fatalf("op %d %s perturbation %+v stayed eligible", op, field, in)
			}
		}
		for v := 0; v < nBaseline; v++ {
			in := base
			in.Baseline = Baseline(v)
			check("baseline", in)
		}
		for v := 0; v < nPair; v++ {
			in := base
			in.Pair = Pair(v)
			check("pair", in)
		}
		for v := 0; v < nLifecycle; v++ {
			in := base
			in.Lifecycle = Lifecycle(v)
			check("lifecycle", in)
		}
		for v := 0; v < nCleanup; v++ {
			in := base
			in.Cleanup = Cleanup(v)
			check("cleanup", in)
		}
		for v := 0; v < nJournal; v++ {
			in := base
			in.Journal = Journal(v)
			check("journal", in)
		}
		for v := 0; v < nLock; v++ {
			in := base
			in.Lock = Lock(v)
			check("lock", in)
		}
		for v := 0; v < nBackup; v++ {
			in := base
			in.Backup = Backup(v)
			check("backup", in)
		}
		for v := 0; v < nRetention; v++ {
			in := base
			in.Retention = Retention(v)
			check("retention", in)
		}
	}
}

func TestInvalidInput(t *testing.T) {
	refused := func(name string, in Inputs) {
		t.Helper()
		d, err := Decide(in)
		if !errors.Is(err, ErrInvalidInput) || d != (Decision{RecoveryRequired, ReasonInvalidInput}) {
			t.Errorf("%s %+v: got %+v %v", name, in, d, err)
		}
	}
	refused("zero", Inputs{})
	unknownOp := eligible
	unknownOp.Operation = OperationUnknown
	refused("unknown operation", unknownOp)
	for _, bad := range []uint8{0, 1} {
		mutations := []struct {
			name string
			set  func(*Inputs)
		}{
			{"operation", func(i *Inputs) { i.Operation = Operation(nOperation + bad*(255-nOperation)) }},
			{"baseline", func(i *Inputs) { i.Baseline = Baseline(nBaseline + bad*(255-nBaseline)) }},
			{"pair", func(i *Inputs) { i.Pair = Pair(nPair + bad*(255-nPair)) }},
			{"lifecycle", func(i *Inputs) { i.Lifecycle = Lifecycle(nLifecycle + bad*(255-nLifecycle)) }},
			{"cleanup", func(i *Inputs) { i.Cleanup = Cleanup(nCleanup + bad*(255-nCleanup)) }},
			{"journal", func(i *Inputs) { i.Journal = Journal(nJournal + bad*(255-nJournal)) }},
			{"lock", func(i *Inputs) { i.Lock = Lock(nLock + bad*(255-nLock)) }},
			{"backup", func(i *Inputs) { i.Backup = Backup(nBackup + bad*(255-nBackup)) }},
			{"retention", func(i *Inputs) { i.Retention = Retention(nRetention + bad*(255-nRetention)) }},
		}
		for _, m := range mutations {
			in := eligible
			m.set(&in)
			refused(m.name+" out of range "+strconv.Itoa(int(bad)), in)
		}
	}
	if (Decision{}).Verdict == Eligible {
		t.Fatal("zero Decision is eligible")
	}
}

func TestRegressionCases(t *testing.T) {
	with := func(f func(*Inputs)) Inputs { in := eligible; f(&in); return in }
	cases := []struct {
		name string
		in   Inputs
		want Decision
	}{
		{"SCM stopped with residual DNS/WFP: cleanup failed", with(func(i *Inputs) { i.Cleanup = CleanupFailed }), Decision{RecoveryRequired, ReasonCleanupFailed}},
		{"SCM stopped with residual DNS/WFP: cleanup unknown", with(func(i *Inputs) { i.Cleanup = CleanupUnknown }), Decision{RecoveryRequired, ReasonCleanupUnknown}},
		{"empty RAS with incomplete journal", with(func(i *Inputs) { i.Journal = JournalIncomplete }), Decision{RecoveryRequired, ReasonJournalIncomplete}},
		{"missing owner after crash", with(func(i *Inputs) { i.Lifecycle = LifecycleUnknown }), Decision{RecoveryRequired, ReasonLifecycleUnknown}},
		{"access denied: baseline", with(func(i *Inputs) { i.Baseline = BaselineUnknown }), Decision{RecoveryRequired, ReasonBaselineUnknown}},
		{"access denied: lock", with(func(i *Inputs) { i.Lock = LockUnknown }), Decision{RecoveryRequired, ReasonLockUnknown}},
		{"access denied: backup", with(func(i *Inputs) { i.Backup = BackupUnknown }), Decision{RecoveryRequired, ReasonBackupUnknown}},
		{"access denied: pair", with(func(i *Inputs) { i.Pair = PairUnknown }), Decision{Blocked, ReasonPairUnknown}},
		{"access denied: retention", with(func(i *Inputs) { i.Retention = RetentionUnknown }), Decision{Blocked, ReasonRetentionUnknown}},
		{"consumed abandonment", with(func(i *Inputs) { i.Lock = LockAbandoned }), Decision{RecoveryRequired, ReasonLockAbandoned}},
		{"preexisting backup", with(func(i *Inputs) { i.Backup = BackupUnresolved }), Decision{RecoveryRequired, ReasonBackupUnresolved}},
		{"insufficient retention", with(func(i *Inputs) { i.Retention = RetentionInsufficient }), Decision{Blocked, ReasonRetentionInsufficient}},
		{"wrong pair", with(func(i *Inputs) { i.Pair = PairMismatch }), Decision{Blocked, ReasonPairMismatch}},
		{"active packet session", with(func(i *Inputs) { i.Lifecycle = LifecyclePacketActive }), Decision{StopThenRetry, ReasonPacketSessionActive}},
		{"idle running packet service", eligible, Decision{Eligible, ReasonEligible}},
		{"native session under packet baseline", with(func(i *Inputs) { i.Lifecycle = LifecycleNativeActive }), Decision{RecoveryRequired, ReasonInconsistentEvidence}},
		{"native enrolled baseline", with(func(i *Inputs) { i.Baseline = BaselineNativeEnrolled }), Decision{Blocked, ReasonNativeMaintenanceBlocked}},
	}
	for _, c := range cases {
		if got, err := Decide(c.in); err != nil || got != c.want {
			t.Errorf("%s: got %+v %v, want %+v", c.name, got, err, c.want)
		}
	}
}

func TestImportsOnlyErrors(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "decision.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Imports) != 1 || f.Imports[0].Path.Value != `"errors"` {
		var got []string
		for _, i := range f.Imports {
			got = append(got, i.Path.Value)
		}
		t.Fatalf("decision.go imports %v, want only errors", got)
	}
}
