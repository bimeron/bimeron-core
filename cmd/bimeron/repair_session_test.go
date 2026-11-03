package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type repairFake struct {
	observation repairObservation
	calls       []string
	fail        string
}

func (f *repairFake) call(s string) error {
	f.calls = append(f.calls, s)
	if f.fail == s {
		return errors.New("injected")
	}
	return nil
}
func (f *repairFake) Inspect(context.Context) (repairObservation, error) {
	return f.observation, f.call("inspect")
}
func (f *repairFake) Install(context.Context) error       { return f.call("install") }
func (f *repairFake) Stop(context.Context) error          { return f.call("stop") }
func (f *repairFake) CleanupProven(context.Context) error { return f.call("cleanup") }
func (f *repairFake) Recover(context.Context) error       { return f.call("recover") }
func (f *repairFake) Start(context.Context) error         { return f.call("start") }
func (f *repairFake) Ready(context.Context) error         { return f.call("ready") }
func (f *repairFake) Rollback(context.Context) error      { return f.call("rollback") }
func TestRepairSequence(t *testing.T) {
	cases := []struct {
		name        string
		observation repairObservation
		consent     repairConsent
		fail        string
		want        []string
		bad         bool
	}{
		{"missing", repairObservation{Missing: true}, repairConsent{}, "", []string{"inspect", "install", "start", "ready"}, false},
		{"stopped", repairObservation{Owned: true, Stopped: true}, repairConsent{}, "", []string{"inspect", "start", "ready"}, false},
		{"healthy", repairObservation{Owned: true}, repairConsent{}, "", []string{"inspect", "ready"}, false},
		{"unknown", repairObservation{}, repairConsent{}, "", []string{"inspect"}, true},
		{"restart", repairObservation{Owned: true, Unresponsive: true}, repairConsent{Disruption: true}, "", []string{"inspect", "stop", "cleanup", "start", "ready"}, false},
		{"cleanup failure", repairObservation{Owned: true, Unresponsive: true}, repairConsent{Disruption: true}, "cleanup", []string{"inspect", "stop", "cleanup"}, true},
		{"stop failure", repairObservation{Owned: true, Unresponsive: true}, repairConsent{Disruption: true}, "stop", []string{"inspect", "stop"}, true},
		{"consent", repairObservation{Owned: true, Unresponsive: true}, repairConsent{}, "", []string{"inspect"}, true},
		{"rollback", repairObservation{Missing: true}, repairConsent{}, "ready", []string{"inspect", "install", "start", "ready", "rollback"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &repairFake{observation: c.observation, fail: c.fail}
			err := runRepair(context.Background(), f, c.consent, nil)
			if (err != nil) != c.bad || !reflect.DeepEqual(f.calls, c.want) {
				t.Fatalf("calls %v error %v", f.calls, err)
			}
		})
	}
}

func TestRepairRejectsContradictoryOwnership(t *testing.T) {
	for _, observation := range []repairObservation{{Missing: true, Unresponsive: true}, {Missing: true, CleanupRequired: true}, {Missing: true, Stopped: true}, {CleanupRequired: true}} {
		f := &repairFake{observation: observation}
		if runRepair(context.Background(), f, repairConsent{true, true}, nil) == nil {
			t.Fatal("unsafe observation accepted")
		}
		if !reflect.DeepEqual(f.calls, []string{"inspect"}) {
			t.Fatal(f.calls)
		}
	}
}
func TestRepairCancellationAndEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &repairFake{observation: repairObservation{Missing: true}}
	if runRepair(ctx, f, repairConsent{}, nil) == nil || len(f.calls) != 0 {
		t.Fatal("canceled repair mutated")
	}
	var stages []repairStage
	f = &repairFake{observation: repairObservation{Missing: true}, fail: "start"}
	if runRepair(context.Background(), f, repairConsent{}, func(s repairStage) { stages = append(stages, s) }) == nil {
		t.Fatal("failed start succeeded")
	}
	if !reflect.DeepEqual(stages, []repairStage{"inspect", "install", "start", "rollback"}) {
		t.Fatal(stages)
	}
	f = &repairFake{observation: repairObservation{Missing: true}, fail: "install"}
	if runRepair(context.Background(), f, repairConsent{}, nil) == nil || !reflect.DeepEqual(f.calls, []string{"inspect", "install"}) {
		t.Fatal("install error did not terminate")
	}
}

type repairReplacementFake struct{ repairFake }

func (f *repairReplacementFake) Replace(context.Context) error { return f.call("replace") }
func TestRepairReplacementSequence(t *testing.T) {
	f := &repairReplacementFake{repairFake{observation: repairObservation{Owned: true, ReplacementRequired: true}}}
	var stages []repairStage
	if err := runRepair(context.Background(), f, repairConsent{Disruption: true}, func(s repairStage) { stages = append(stages, s) }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.calls, []string{"inspect", "replace", "ready"}) || !reflect.DeepEqual(stages, []repairStage{"inspect", "replace", "verify", "ready"}) {
		t.Fatal(f.calls, stages)
	}
	f = &repairReplacementFake{repairFake{observation: repairObservation{Owned: true, ReplacementRequired: true}}}
	if runRepair(context.Background(), f, repairConsent{}, nil) == nil || !reflect.DeepEqual(f.calls, []string{"inspect"}) {
		t.Fatal("replacement bypassed consent")
	}
}

type cancelAfterInstallFake struct {
	repairFake
	cancel context.CancelFunc
}

func (f *cancelAfterInstallFake) Install(context.Context) error {
	err := f.call("install")
	f.cancel()
	return err
}
func TestRepairCancellationAfterInstallRollsBack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &cancelAfterInstallFake{repairFake: repairFake{observation: repairObservation{Missing: true}}, cancel: cancel}
	if runRepair(ctx, f, repairConsent{}, nil) == nil {
		t.Fatal("canceled install reported ready")
	}
	if !reflect.DeepEqual(f.calls, []string{"inspect", "install", "rollback"}) {
		t.Fatal(f.calls)
	}
}

func TestStoppedReplacementNeedsNoDisruptionConsent(t *testing.T) {
	f := &repairReplacementFake{repairFake{observation: repairObservation{Owned: true, Stopped: true, ReplacementRequired: true}}}
	if err := runRepair(context.Background(), f, repairConsent{}, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.calls, []string{"inspect", "replace", "ready"}) {
		t.Fatal(f.calls)
	}
}
func TestStoppedReplacementStillRequiresNetworkConsent(t *testing.T) {
	f := &repairReplacementFake{repairFake{observation: repairObservation{Owned: true, Stopped: true, ReplacementRequired: true, CleanupRequired: true}}}
	if err := runRepair(context.Background(), f, repairConsent{}, nil); err == nil {
		t.Fatal("network recovery bypassed consent")
	}
	if !reflect.DeepEqual(f.calls, []string{"inspect"}) {
		t.Fatal(f.calls)
	}
}
