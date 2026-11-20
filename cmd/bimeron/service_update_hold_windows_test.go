//go:build windows

package main

import (
	"errors"
	"golang.org/x/sys/windows/svc"
	"strings"
	"testing"

	"bimeron/core"
	"bimeron/internal/control"
)

// The updater keeps protection only when the installed service accepted the
// request while a run owns protection; every other answer releases it as
// before and says so.
func TestUpdateHoldMessage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answer  control.Response
		err     error
		kept    bool
		message string
	}{
		{"active", control.Response{Status: core.Status{KillSwitch: core.KillSwitchActive}}, nil, true, "requested"},
		{"holding", control.Response{Status: core.Status{KillSwitch: core.KillSwitchHolding}}, nil, true, "requested"},
		{"existing hold", control.Response{Status: core.Status{KillSwitch: core.KillSwitchResidual, ResidualReason: core.ResidualUpdate}}, nil, true, "requested"},
		{"residual", control.Response{Status: core.Status{KillSwitch: core.KillSwitchResidual}}, nil, false, "stays installed"},
		{"no protection", control.Response{}, nil, false, ""},
		{"old service", control.Response{Version: control.Version, Instance: "old", Error: "invalid_request"}, errors.New("invalid_request"), false, "cannot keep"},
		{"unreachable", control.Response{}, errors.New("readiness service identity rejected"), false, ""},
	} {
		kept, message, err := updateHoldMessage(tc.answer, tc.err)
		if kept != tc.kept || !strings.Contains(message, tc.message) || (tc.message == "" && message != "") {
			t.Fatal(tc.name, kept, message)
		}
		if tc.err != nil && tc.answer.Error == "" {
			if err == nil {
				t.Fatal(tc.name, "ambiguous response allowed stop")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !tc.kept && tc.err != nil && !strings.Contains(message, "released") {
			t.Fatal(tc.name, "warning does not say protection is released", message)
		}
	}
}

func TestUpdateHoldNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name                                                             string
		supported, olderPrepare, reject, wrongInstance, wrongID, success bool
	}{
		{name: "transactional", supported: true, success: true},
		{name: "legacy fallback", reject: true, success: true},
		{name: "old prepare", olderPrepare: true},
		{name: "ambiguous legacy acceptance"},
		{name: "lost acknowledgement", supported: true, reject: true},
		{name: "changed instance", supported: true, wrongInstance: true},
		{name: "changed transaction", supported: true, wrongID: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared := false
			a, err := negotiateUpdateHold(func(r control.Request) (control.Response, error) {
				a := control.Response{Version: control.Version, Instance: "old"}
				if r.Command == "hello" {
					a.Core = &core.BuildDetails{Version: "1"}
					a.UpdateStopSupported = tc.supported
					return a, nil
				}
				prepared = true
				if tc.reject {
					a.Error = "invalid_request"
					return a, errors.New(a.Error)
				}
				a.ID, a.UpdateTransaction = r.ID, r.ID
				if tc.wrongInstance {
					a.Instance = "foreign"
				}
				if tc.wrongID {
					a.UpdateTransaction = "foreign"
				}
				return a, nil
			}, func() (control.Response, error) {
				return control.Response{Version: control.Version, Instance: "old", Capabilities: &core.Capabilities{KillSwitchUpdateHold: tc.olderPrepare}}, nil
			})
			_, _, err = updateHoldMessage(a, err)
			if (err == nil) != tc.success || prepared == tc.olderPrepare {
				t.Fatal(prepared, err)
			}
		})
	}
}

func TestRequiredUpdateProtectionReadiness(t *testing.T) {
	profile := strings.Repeat("ab", 32)
	s := core.Status{State: core.Failed, KillSwitch: core.KillSwitchResidual, LastError: "cleanup_failed_run_recover", ResidualProfile: profile, ResidualReason: core.ResidualUpdate}
	if err := verifyRetainedUpdate(s, profile, profile); err != nil {
		t.Fatal(err)
	}
	if verifyRetainedUpdate(s, profile, "") == nil {
		t.Fatal("foreign transaction accepted")
	}
	s.ResidualReason = ""
	if verifyRetainedUpdate(s, profile, profile) == nil {
		t.Fatal("ordinary residual accepted")
	}
	if verifyRetainedUpdate(core.Status{State: core.Disconnected}, profile, "") == nil {
		t.Fatal("disconnected accepted")
	}
}

func TestOptInRollbackRequiresFreshPreparation(t *testing.T) {
	for _, fail := range []bool{false, true} {
		prepared, stopped := false, false
		err := stopForRollback(true, func() (svc.Status, error) { return svc.Status{State: svc.Running}, nil }, func() (control.Response, error) {
			prepared = true
			if fail {
				return control.Response{}, errors.New("readiness unavailable")
			}
			return control.Response{UpdateTransaction: "test"}, nil
		}, func(id string, required bool) error {
			if id != "test" {
				t.Fatal(id)
			}
			stopped = true
			return nil
		})
		if !prepared || stopped == fail || (err != nil) != fail {
			t.Fatal(prepared, stopped, err)
		}
	}
}
