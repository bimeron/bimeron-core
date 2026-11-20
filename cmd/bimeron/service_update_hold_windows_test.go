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
		{"active", control.Response{Status: core.Status{KillSwitch: core.KillSwitchActive}}, nil, true, "is kept"},
		{"holding", control.Response{Status: core.Status{KillSwitch: core.KillSwitchHolding}}, nil, true, "is kept"},
		{"existing hold", control.Response{Status: core.Status{KillSwitch: core.KillSwitchResidual, ResidualReason: core.ResidualUpdate}}, nil, true, "is kept"},
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

func TestOptInRollbackRequiresFreshPreparation(t *testing.T) {
	for _, fail := range []bool{false, true} {
		prepared, stopped := false, false
		err := stopForRollback(true, func() (svc.Status, error) { return svc.Status{State: svc.Running}, nil }, func() (control.Response, error) {
			prepared = true
			if fail {
				return control.Response{}, errors.New("readiness unavailable")
			}
			return control.Response{}, nil
		}, func() error { stopped = true; return nil })
		if !prepared || stopped == fail || (err != nil) != fail {
			t.Fatal(prepared, stopped, err)
		}
	}
}
