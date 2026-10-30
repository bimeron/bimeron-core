//go:build windows && core_reader_proof

package nativeenrollment

import (
	"encoding/hex"
	"os"
	"reflect"
	"testing"
)

// TestCoreReaderProof reads exactly one parent-provisioned disposable VM case.
// It never provisions, writes, repairs or cleans up any filesystem object.
func TestCoreReaderProof(t *testing.T) {
	if os.Getenv("CORE_READER_PROOF_ENABLE") != "1" {
		t.Skip("protected native cases UNEXECUTED: explicit parent-only VM opt-in required")
	}
	run := os.Getenv("CORE_READER_PROOF_RUN")
	if !coreReaderProofGUID(run) {
		t.Fatal("CORE_READER_PROOF_RUN must be a canonical lowercase nonzero GUID")
	}
	name := os.Getenv("CORE_READER_PROOF_CASE")
	want := Observation{Result: UnsafeRead}
	decision := Decision{RefuseProtectedAdmission, Refuse, UnsafeEvidence}
	golden := ""
	switch name {
	case "clean", "clean-match", "clean-stale":
		golden = "42494d4e454e52310100010000000000010000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000"
		decision = Decision{LegacyUnchanged, EligibleModelOnly, CleanModelOnly}
	case "pending", "pending-match", "pending-stale":
		golden = "42494d4e454e52310100020000000000010000000000000001000000000000000000000000000000020000000000000000000000000000000000000000000000"
		decision = Decision{RefuseProtectedAdmission, Refuse, PendingReason}
	case "absent-core", "absent-container", "absent-core-bound", "absent-container-bound":
		want.Result = ProtectedAbsence
		want.First = Snapshot{View: NativeView, Security: Protected}
		want.Second = want.First
		decision = Decision{LegacyUnchanged, Unavailable, NotEnrolled}
	case "missing-prefix", "missing-leaf", "unsafe-owner", "unsafe-dacl", "case-sensitive", "reparse", "multilink", "sharing":
		// Parent must independently verify the intended offending object;
		// another unsafe ancestor is not evidence for the named case.
	default:
		t.Fatal("CORE_READER_PROOF_CASE is not a closed reader proof case")
	}
	if golden != "" {
		b, err := hex.DecodeString(golden)
		if err != nil || len(b) != 64 {
			t.Fatal("invalid Core 64-byte golden")
		}
		want.Result = Present
		want.First = Snapshot{View: NativeView, Security: Protected, Bytes: b}
		want.Second = want.First
	}
	switch name {
	case "clean-match", "pending-match":
		want.Expected = &Binding{Installation: [16]byte{1}, Generation: 1}
	case "clean-stale", "pending-stale":
		want.Expected = &Binding{Installation: [16]byte{1}, Generation: 2}
		decision = Decision{RefuseProtectedAdmission, Refuse, BindingMismatch}
	case "absent-core-bound", "absent-container-bound":
		want.Expected = &Binding{Installation: [16]byte{1}, Generation: 1}
		decision = Decision{RefuseProtectedAdmission, Refuse, BindingMismatch}
	}
	folder, err := nativeProgramFiles()
	if err != nil {
		t.Fatalf("native Program Files unavailable; case UNEXECUTED: %v", err)
	}
	got := readNativeFolderPrefix(folder, []string{"BimeronCoreReaderProof", run, name}, want.Expected)
	if got.Expected != want.Expected || !reflect.DeepEqual(got, want) {
		t.Fatalf("native storage observation: got %+v; want %+v", got, want)
	}
	if d := Evaluate(got); d != decision {
		t.Fatalf("storage/model decision: got %+v; want %+v", d, decision)
	}
	t.Logf("native storage/model evidence only: run=%s case=%s; enrollment DISABLED", run, name)
}

func coreReaderProofGUID(s string) bool {
	if len(s) != 36 || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
