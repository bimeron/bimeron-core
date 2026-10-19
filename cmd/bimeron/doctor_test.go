package main

import (
	"context"
	"encoding/json"
	"errors"
	"bimeron/core"
	"bimeron/internal/control"
	"bimeron/internal/telemetry"
	"strings"
	"testing"
)

func TestDoctorRedactsErrorsAndEventMessages(t *testing.T) {
	secret := "ssconf://private.example/secret-token"
	call := func(_ context.Context, r control.Request) (control.Response, error) {
		a := control.Response{Instance: "one", Status: core.Status{State: core.Connected, LastError: secret}}
		switch r.Command {
		case "stats":
			a.Stats = &telemetry.Snapshot{BytesUp: 17}
		case "events":
			a.Events = []control.LoggedEvent{{Event: core.Event{State: core.Connected, Code: "connected", Message: secret, LastError: secret}}}
		}
		return a, nil
	}
	report := gatherDiagnostics(context.Background(), call, func(context.Context) []diagnosticCheck { return nil })
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || strings.Contains(string(data), "private.example") {
		t.Fatal("report leaked secrets")
	}
	if report.Status.LastError != "redacted_error" || report.Stats.BytesUp != 17 || len(report.Events) != 1 {
		t.Fatal(report)
	}
}
func TestDoctorContinuesWithoutDaemon(t *testing.T) {
	report := gatherDiagnostics(context.Background(), func(context.Context, control.Request) (control.Response, error) {
		return control.Response{}, errors.New("sensitive details")
	}, func(context.Context) []diagnosticCheck { return []diagnosticCheck{{Name: "host", Result: "observed"}} })
	if report.Status != nil || len(report.Checks) != 2 || report.Checks[0].Result != "unavailable" {
		t.Fatal(report)
	}
}
func TestDoctorRejectsMixedDaemonInstances(t *testing.T) {
	report := gatherDiagnostics(context.Background(), func(_ context.Context, r control.Request) (control.Response, error) {
		if r.Command == "status" {
			return control.Response{Instance: "old"}, nil
		}
		return control.Response{Instance: "new", Stats: &telemetry.Snapshot{BytesUp: 9}}, nil
	}, func(context.Context) []diagnosticCheck { return nil })
	if report.Stats != nil || len(report.Checks) != 3 {
		t.Fatal(report)
	}
}
