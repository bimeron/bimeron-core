// Package nativeenrollment models disabled enrollment offline and includes a
// disconnected read-only Windows file observer. It grants no runtime permission
// and is not connected to production admissions.
package nativeenrollment

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type Phase uint8

const (
	Clean   Phase = 1
	Pending Phase = 2
)

// Record includes hypothetical clean fixtures; clean is not installer success.
type Record struct {
	Phase                   Phase
	Generation              uint64
	Installation, Operation [16]byte
}

var errRecord = errors.New("invalid native enrollment record")

func valid(r Record) bool {
	return r.Generation != 0 && r.Installation != [16]byte{} && ((r.Phase == Clean && r.Operation == [16]byte{}) || (r.Phase == Pending && r.Operation != [16]byte{}))
}
func Decode(b []byte) (Record, error) {
	if len(b) != 64 || string(b[:8]) != "BIMNENR1" || binary.LittleEndian.Uint16(b[8:10]) != 1 || !bytes.Equal(b[11:16], make([]byte, 5)) || !bytes.Equal(b[56:64], make([]byte, 8)) {
		return Record{}, errRecord
	}
	r := Record{Phase: Phase(b[10]), Generation: binary.LittleEndian.Uint64(b[16:24])}
	copy(r.Installation[:], b[24:40])
	copy(r.Operation[:], b[40:56])
	if !valid(r) {
		return Record{}, errRecord
	}
	return r, nil
}
func Encode(r Record) ([]byte, error) {
	if !valid(r) {
		return nil, errRecord
	}
	b := make([]byte, 64)
	copy(b, "BIMNENR1")
	binary.LittleEndian.PutUint16(b[8:10], 1)
	b[10] = byte(r.Phase)
	binary.LittleEndian.PutUint64(b[16:24], r.Generation)
	copy(b[24:40], r.Installation[:])
	copy(b[40:56], r.Operation[:])
	return b, nil
}

type ReadResult uint8

const (
	ResultUnknown ReadResult = iota
	ProtectedAbsence
	Present
	UnsafeRead
)

type View uint8

const (
	ViewUnknown View = iota
	NativeView
	OtherView
)

// Security is an explicit offline classification, not native ACL verification.
// Protected requires trusted ownership, protected non-null DACL and safe ancestors.
// Unknown ACEs, failed reads or effective untrusted mutation must classify unsafe.
type Security uint8

const (
	SecurityUnknown Security = iota
	Protected
	UnsafeSecurity
)

type Snapshot struct {
	View     View
	Security Security
	Bytes    []byte
}
type Binding struct {
	Installation [16]byte
	Generation   uint64
}
type Observation struct {
	Result        ReadResult
	First, Second Snapshot
	Expected      *Binding
}
type PacketDisposition uint8

const (
	RefuseProtectedAdmission PacketDisposition = iota
	LegacyUnchanged
)

type NativeDisposition uint8

const (
	Refuse NativeDisposition = iota
	Unavailable
	EligibleModelOnly
)

type Reason string

const (
	NotEnrolled     Reason = "notEnrolled"
	CleanModelOnly  Reason = "cleanModelOnly"
	PendingReason   Reason = "pending"
	UnsafeEvidence  Reason = "unsafeEvidence"
	WrongView       Reason = "wrongView"
	InvalidRecord   Reason = "invalidRecord"
	ChangedSnapshot Reason = "changedSnapshot"
	BindingMismatch Reason = "bindingMismatch"
)

type Decision struct {
	Packet PacketDisposition
	Native NativeDisposition
	Reason Reason
}

// Evaluate checks evidence, view, records, equality, bindings and phase in order.
// Matching samples cannot detect unobserved ABA or provide atomic admission.
func Evaluate(o Observation) Decision {
	deny := func(r Reason) Decision { return Decision{RefuseProtectedAdmission, Refuse, r} }
	if (o.Result != ProtectedAbsence && o.Result != Present) || o.First.Security != Protected || o.Second.Security != Protected {
		return deny(UnsafeEvidence)
	}
	if o.First.View != NativeView || o.Second.View != NativeView {
		return deny(WrongView)
	}
	if o.Result == ProtectedAbsence {
		if len(o.First.Bytes) != 0 || len(o.Second.Bytes) != 0 {
			return deny(UnsafeEvidence)
		}
		return Decision{LegacyUnchanged, Unavailable, NotEnrolled}
	}
	r, e := Decode(o.First.Bytes)
	if e != nil {
		return deny(InvalidRecord)
	}
	if _, e = Decode(o.Second.Bytes); e != nil {
		return deny(InvalidRecord)
	}
	if !bytes.Equal(o.First.Bytes, o.Second.Bytes) {
		return deny(ChangedSnapshot)
	}
	if b := o.Expected; b != nil && (b.Generation == 0 || b.Generation != r.Generation || b.Installation != r.Installation) {
		return deny(BindingMismatch)
	}
	if r.Phase == Pending {
		return deny(PendingReason)
	}
	return Decision{LegacyUnchanged, EligibleModelOnly, CleanModelOnly}
}

type Event uint8

const (
	HostLost Event = iota + 1
	Reboot
	LocalCommitCallback
	LocalRollbackCallback
	ChildRemoval
	RollbackDisabled
	LocalFinalize
	UpdaterLost
)

// AfterPendingEvent preserves pending: none of these events proves outer completion.
func AfterPendingEvent(r Record, e Event) (Record, error) {
	if !valid(r) || r.Phase != Pending {
		return Record{}, errRecord
	}
	if e < HostLost || e > UpdaterLost {
		return Record{}, errors.New("invalid pending event")
	}
	return r, nil
}
