//go:build windows

package main

import (
	"errors"
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
		{"residual", control.Response{Status: core.Status{KillSwitch: core.KillSwitchResidual}}, nil, false, "stays installed"},
		{"no protection", control.Response{}, nil, false, ""},
		{"old service", control.Response{Error: "invalid_request"}, errors.New("invalid_request"), false, "cannot keep"},
		{"unreachable", control.Response{}, errors.New("readiness service identity rejected"), false, "could not ask"},
	} {
		kept, message := updateHoldMessage(tc.answer, tc.err)
		if kept != tc.kept || !strings.Contains(message, tc.message) || (tc.message == "" && message != "") {
			t.Fatal(tc.name, kept, message)
		}
		if !tc.kept && tc.err != nil && !strings.Contains(message, "released") {
			t.Fatal(tc.name, "warning does not say protection is released", message)
		}
	}
}
