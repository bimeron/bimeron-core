package nativeenrollment

import "testing"

func TestUpdateCompatibilityAndOutcomes(t *testing.T) {
	op, _, _ := updateFixture()
	set := UpdateInventory{Runnable: []UpdateImage{op.Candidate}, Rollback: []UpdateImage{op.Rollback}, RunnableScope: CompleteInventory, RollbackScope: CompleteInventory}
	if err := CheckUpdateInventory(op, set); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*UpdateInventory){
		func(s *UpdateInventory) { s.RunnableScope = 0 }, func(s *UpdateInventory) { s.RollbackScope = 0 },
		func(s *UpdateInventory) { s.Runnable = nil }, func(s *UpdateInventory) { s.Rollback = nil },
		func(s *UpdateInventory) { bad := op.Candidate; bad.Protocol++; s.Runnable = append(s.Runnable, bad) },
		func(s *UpdateInventory) { bad := op.Rollback; bad.Digest[0]++; s.Rollback = append(s.Rollback, bad) },
	} {
		s := set
		change(&s)
		if CheckUpdateInventory(op, s) == nil {
			t.Fatal("unknown or incompatible set accepted")
		}
	}
	for _, state := range []ServiceState{ServiceRunning, ServiceStopped} {
		op.Original = state
		for _, outcome := range []UpdateOutcome{ExecutionUnknown, CandidateHealthy, RestoredRunningSCMOnly, RestoredStopped, RollbackBlocked} {
			got, err := ObserveUpdateOutcome(op, outcome)
			valid := outcome == ExecutionUnknown || outcome == RollbackBlocked || state == ServiceRunning && (outcome == CandidateHealthy || outcome == RestoredRunningSCMOnly) || state == ServiceStopped && outcome == RestoredStopped
			if (err == nil) != valid {
				t.Fatalf("state %v outcome %v: %v", state, outcome, err)
			}
			if err == nil && got != op.Pending {
				t.Fatal("outcome changed pending")
			}
		}
	}
	if _, err := ObserveUpdateOutcome(op, UpdateOutcome(255)); err == nil {
		t.Fatal("unknown outcome accepted")
	}
	// Complete lists classify fixtures only; they cannot prevent later old-host return.
}

func TestInvalidOperationBindings(t *testing.T) {
	op, _, _ := updateFixture()
	for _, change := range []func(*UpdateOperation){
		func(o *UpdateOperation) { o.Pending = fixture(Clean) },
		func(o *UpdateOperation) { o.Pending.Installation = [16]byte{} },
		func(o *UpdateOperation) { o.Pending.Operation = [16]byte{} },
		func(o *UpdateOperation) { o.Candidate.Role = "" },
		func(o *UpdateOperation) { o.Rollback.Protocol = 0 },
		func(o *UpdateOperation) { o.Rollback = o.Candidate },
		func(o *UpdateOperation) { o.Rollback.File = o.Candidate.File },
		func(o *UpdateOperation) { o.Original = ServiceState(255) },
	} {
		o := op
		change(&o)
		if _, err := ObserveUpdateOutcome(o, ExecutionUnknown); err == nil {
			t.Fatal("invalid binding accepted")
		}
	}
	op.Original = ServiceStopped
	if got, err := ObserveUpdateOutcome(op, CandidateInstalledStopped); err != nil || got != op.Pending {
		t.Fatal(got, err)
	}
}
