package nativeenrollment

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func fixture(p Phase) Record {
	r := Record{Phase: p, Generation: 1}
	r.Installation[0] = 1
	if p == Pending {
		r.Operation[0] = 2
	}
	return r
}
func sample(r Record) Snapshot {
	b, e := Encode(r)
	if e != nil {
		panic(e)
	}
	return Snapshot{View: NativeView, Security: Protected, Bytes: b}
}
func present(r Record) Observation {
	s := sample(r)
	return Observation{Result: Present, First: s, Second: s}
}
func reason(t *testing.T, o Observation, w Reason) {
	t.Helper()
	d := Evaluate(o)
	if d.Reason != w {
		t.Fatalf("got %+v, want %v", d, w)
	}
	if w != NotEnrolled && w != CleanModelOnly && (d.Packet != RefuseProtectedAdmission || d.Native != Refuse) {
		t.Fatalf("unsafe decision %+v", d)
	}
}

func TestCodecGolden(t *testing.T) {
	for _, p := range []Phase{Clean, Pending} {
		r := fixture(p)
		golden := "42494d4e454e52310100010000000000010000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000"
		if p == Pending {
			golden = "42494d4e454e52310100020000000000010000000000000001000000000000000000000000000000020000000000000000000000000000000000000000000000"
		}
		want, _ := hex.DecodeString(golden)
		b, e := Encode(r)
		if e != nil || !bytes.Equal(b, want) {
			t.Fatalf("golden %x %v", b, e)
		}
		for i := 0; i < 10; i++ {
			got, e := Decode(want)
			if e != nil || got != r {
				t.Fatalf("roundtrip %+v %v", got, e)
			}
			again, _ := Encode(got)
			if !bytes.Equal(again, want) {
				t.Fatal("nondeterministic")
			}
		}
	}
	r := fixture(Clean)
	r.Generation = ^uint64(0)
	b, e := Encode(r)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Decode(b)
	if e != nil || got != r {
		t.Fatal("max generation is valid, without increment authority")
	}
}
func TestCodecInvalid(t *testing.T) {
	valid, _ := Encode(fixture(Clean))
	for _, n := range []int{0, 63, 65} {
		if _, e := Decode(make([]byte, n)); e == nil {
			t.Fatalf("length %d", n)
		}
	}
	for _, i := range []int{0, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 40, 56, 57, 58, 59, 60, 61, 62, 63} {
		b := bytes.Clone(valid)
		if i == 16 || i == 24 {
			b[i] = 0
		} else {
			b[i] = 255
		}
		if _, e := Decode(b); e == nil {
			t.Fatalf("accepted mutation at %d", i)
		}
	}
	for _, r := range []Record{{}, {Phase: Phase(3), Generation: 1, Installation: [16]byte{1}}, {Phase: Clean, Generation: 1, Installation: [16]byte{1}, Operation: [16]byte{1}}, {Phase: Pending, Generation: 1, Installation: [16]byte{1}}} {
		if _, e := Encode(r); e == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
}
func TestEvidenceAndBindings(t *testing.T) {
	absence := Observation{Result: ProtectedAbsence, First: Snapshot{View: NativeView, Security: Protected}, Second: Snapshot{View: NativeView, Security: Protected}}
	d := Evaluate(absence)
	if d != (Decision{LegacyUnchanged, Unavailable, NotEnrolled}) {
		t.Fatal(d)
	}
	reason(t, Observation{}, UnsafeEvidence)
	// These are explicit classifications, not native ACL parsing or enforcement.
	for _, name := range []string{"untrusted owner", "absent DACL", "null DACL", "inherited mutation", "generic write", "generic all", "create link", "delete", "WRITE_DAC", "WRITE_OWNER", "unknown effective ACE", "descriptor read failed", "access denied", "insecure ancestor"} {
		t.Run(name, func(t *testing.T) {
			o := absence
			o.Second.Security = UnsafeSecurity
			reason(t, o, UnsafeEvidence)
			o = present(fixture(Clean))
			o.First.Security = SecurityUnknown
			reason(t, o, UnsafeEvidence)
		})
	}
	for _, v := range []View{ViewUnknown, OtherView} {
		o := absence
		o.First.View = v
		reason(t, o, WrongView)
		o = present(fixture(Clean))
		o.Second.View = v
		reason(t, o, WrongView)
	}
	o := present(fixture(Clean))
	if Evaluate(o) != (Decision{LegacyUnchanged, EligibleModelOnly, CleanModelOnly}) {
		t.Fatal(Evaluate(o))
	}
	for _, field := range []string{"generation", "installation", "phase"} {
		r := fixture(Clean)
		switch field {
		case "generation":
			r.Generation++
		case "installation":
			r.Installation[1] = 2
		case "phase":
			r = fixture(Pending)
		}
		o := present(fixture(Clean))
		o.Second = sample(r)
		reason(t, o, ChangedSnapshot)
	}
	o.Second.Bytes = []byte{1}
	reason(t, o, InvalidRecord)
	o = present(fixture(Clean))
	for _, binding := range []Binding{{Installation: [16]byte{1}}, {Installation: [16]byte{2}, Generation: 1}, {Installation: [16]byte{1}, Generation: 2}} {
		o.Expected = &binding
		reason(t, o, BindingMismatch)
	}
	b := Binding{Installation: [16]byte{1}, Generation: 1}
	o.Expected = &b
	reason(t, o, CleanModelOnly)
	// A -> B -> A between samples is invisible: equality is not atomic admission or replay protection.
	o = present(fixture(Clean))
	reason(t, o, CleanModelOnly)
}
func TestPendingEvents(t *testing.T) {
	r := fixture(Pending)
	original, _ := Encode(r)
	// Mutex-handle disappearance (hostLost) supplies no terminal authority.
	for _, event := range []Event{HostLost, Reboot, LocalCommitCallback, LocalRollbackCallback, ChildRemoval, RollbackDisabled, LocalFinalize, UpdaterLost} {
		var e error
		r, e = AfterPendingEvent(r, event)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := Encode(r)
		if !bytes.Equal(b, original) {
			t.Fatal("pending changed")
		}
		reason(t, present(r), PendingReason)
	}
	for _, r := range []Record{fixture(Clean), {}} {
		if _, e := AfterPendingEvent(r, HostLost); e == nil {
			t.Fatal("accepted non-pending")
		}
	}
	for _, e := range []Event{0, 9, 255} {
		if _, err := AfterPendingEvent(fixture(Pending), e); err == nil {
			t.Fatal("accepted unknown event")
		}
	}
}

func TestValidationOrderAndInvalidEncoding(t *testing.T) {
	for _, mutate := range []func(*Record){func(r *Record) { r.Generation = 0 }, func(r *Record) { r.Installation = [16]byte{} }, func(r *Record) { r.Phase = 0 }} {
		r := fixture(Clean)
		mutate(&r)
		if _, e := Encode(r); e == nil {
			t.Fatalf("encoded invalid %+v", r)
		}
	}
	pending, _ := Encode(fixture(Pending))
	clear(pending[40:56])
	if _, e := Decode(pending); e == nil {
		t.Fatal("decoded pending without operation")
	}
	o := present(fixture(Pending))
	o.Expected = &Binding{}
	o.Second = sample(fixture(Clean))
	o.First.Bytes = nil
	o.First.View = OtherView
	o.First.Security = UnsafeSecurity
	reason(t, o, UnsafeEvidence)
	o.First.Security = Protected
	reason(t, o, WrongView)
	o.First.View = NativeView
	reason(t, o, InvalidRecord)
	o.First = sample(fixture(Pending))
	reason(t, o, ChangedSnapshot)
	o.Second = sample(fixture(Pending))
	reason(t, o, BindingMismatch)
	o.Expected = nil
	reason(t, o, PendingReason)
	o.Result = UnsafeRead
	reason(t, o, UnsafeEvidence)
	// Unknown enum values fail closed even when the other fields look valid.
	o = present(fixture(Clean))
	o.Result = ReadResult(255)
	reason(t, o, UnsafeEvidence)
	o = present(fixture(Clean))
	o.First.Security = Security(255)
	reason(t, o, UnsafeEvidence)
	o = present(fixture(Clean))
	o.Second.View = View(255)
	reason(t, o, WrongView)
}

func TestProtectedAbsencePriorBinding(t *testing.T) {
	for _, b := range []Binding{{Installation: [16]byte{1}, Generation: 1}, {Installation: [16]byte{9}, Generation: 42}, {}, {Installation: [16]byte{1}}, {Generation: 1}} {
		o := Observation{Result: ProtectedAbsence, First: Snapshot{View: NativeView, Security: Protected}, Second: Snapshot{View: NativeView, Security: Protected}, Expected: &b}
		reason(t, o, BindingMismatch)
		if o.Expected != &b {
			t.Fatal("binding discarded")
		}
		o.First.Bytes = []byte{1}
		reason(t, o, UnsafeEvidence)
		o.First.Bytes = nil
		o.First.View = OtherView
		reason(t, o, WrongView)
		o.First.Security = UnsafeSecurity
		reason(t, o, UnsafeEvidence)
	}
	o := Observation{Result: ProtectedAbsence, First: Snapshot{View: NativeView, Security: Protected}, Second: Snapshot{View: NativeView, Security: Protected}}
	if d := Evaluate(o); d != (Decision{LegacyUnchanged, Unavailable, NotEnrolled}) {
		t.Fatal(d)
	}
}
