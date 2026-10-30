package nativeenrollment

import "testing"

func updateFixture() (UpdateOperation, HealthRequest, HealthEvidence) {
	image := UpdateImage{Volume: 1, File: [16]byte{1}, Digest: [32]byte{1}, Role: "service", Version: "2", Protocol: 1}
	op := UpdateOperation{Pending: fixture(Pending), Candidate: image, Rollback: image, Original: ServiceRunning}
	op.Rollback.File[0] = 2
	op.Rollback.Version = "1"
	req := HealthRequest{Operation: op, Challenge: [32]byte{1}, Process: ProcessIdentity{PID: 7, Created: 9}}
	evidence := HealthEvidence{Binding: op.Pending, Challenge: req.Challenge, Peer: req.Process, HeldProcess: req.Process, HeldImage: image, Role: image.Role, Version: image.Version, Protocol: image.Protocol}
	return op, req, evidence
}

func TestHealthExactEvidence(t *testing.T) {
	_, req, evidence := updateFixture()
	if err := CheckUpdateHealth(req, evidence); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*HealthEvidence){
		"missing peer":      func(e *HealthEvidence) { e.Peer = ProcessIdentity{} },
		"PID reuse":         func(e *HealthEvidence) { e.Peer.Created++ },
		"held PID":          func(e *HealthEvidence) { e.HeldProcess.PID++ },
		"missing image":     func(e *HealthEvidence) { e.HeldImage = UpdateImage{} },
		"wrong volume":      func(e *HealthEvidence) { e.HeldImage.Volume++ },
		"wrong file":        func(e *HealthEvidence) { e.HeldImage.File[0]++ },
		"wrong digest":      func(e *HealthEvidence) { e.HeldImage.Digest[0]++ },
		"role":              func(e *HealthEvidence) { e.Role = "foreground" },
		"version":           func(e *HealthEvidence) { e.Version = "1" },
		"protocol":          func(e *HealthEvidence) { e.Protocol++ },
		"replay":            func(e *HealthEvidence) { e.Challenge[0]++ },
		"missing challenge": func(e *HealthEvidence) { e.Challenge = [32]byte{} },
		"generation":        func(e *HealthEvidence) { e.Binding.Generation++ },
		"installation":      func(e *HealthEvidence) { e.Binding.Installation[0]++ },
		"operation":         func(e *HealthEvidence) { e.Binding.Operation[0]++ },
		"clean":             func(e *HealthEvidence) { e.Binding = fixture(Clean) },
	} {
		t.Run(name, func(t *testing.T) {
			e := evidence
			change(&e)
			if CheckUpdateHealth(req, e) == nil {
				t.Fatal("incomplete or conflicting evidence accepted")
			}
		})
	}
	for _, change := range []func(*HealthRequest){
		func(r *HealthRequest) { r.Challenge = [32]byte{} },
		func(r *HealthRequest) { r.Process = ProcessIdentity{} },
		func(r *HealthRequest) { r.Operation.Pending.Generation = 0 },
		func(r *HealthRequest) { r.Operation.Candidate.Digest = [32]byte{} },
		func(r *HealthRequest) { r.Operation.Rollback = UpdateImage{} },
		func(r *HealthRequest) { r.Operation.Original = 0 },
	} {
		r := req
		change(&r)
		if CheckUpdateHealth(r, evidence) == nil {
			t.Fatal("invalid request accepted")
		}
	}
	// The caller must generate/consume fresh challenges. Repeated identical offline
	// evidence cannot reveal replay; this function owns no transport or nonce store.
	if err := CheckUpdateHealth(req, evidence); err != nil {
		t.Fatal(err)
	}
}
