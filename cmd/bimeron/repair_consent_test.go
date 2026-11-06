package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestRepairFreshRiskConsentInSameTransaction(t *testing.T) {
	for _, deny := range []bool{false, true} {
		f := &repairFake{observation: repairObservation{Owned: true, Unresponsive: true, CleanupRequired: true}}
		var challenges []string
		err := runRepairWithConsent(context.Background(), f, repairConsent{}, nil, func(ctx context.Context, kind string) (bool, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("consent outside session budget")
			}
			if !reflect.DeepEqual(f.calls, []string{"inspect"}) {
				t.Fatal("mutation before consent", f.calls)
			}
			challenges = append(challenges, kind)
			return !deny, nil
		})
		if deny {
			if err == nil || !reflect.DeepEqual(f.calls, []string{"inspect"}) || len(challenges) != 1 {
				t.Fatal(err, f.calls, challenges)
			}
		} else {
			if err != nil || !reflect.DeepEqual(challenges, []string{"disruption", "network-recovery"}) || !reflect.DeepEqual(f.calls, []string{"inspect", "inspect", "stop", "cleanup", "recover", "cleanup", "start", "ready"}) {
				t.Fatal(err, f.calls, challenges)
			}
		}
	}
	f := &repairFake{observation: repairObservation{Owned: true, CleanupRequired: true}}
	err := runRepairWithConsent(context.Background(), f, repairConsent{}, nil, func(context.Context, string) (bool, error) { return false, context.DeadlineExceeded })
	if !errors.Is(err, context.DeadlineExceeded) || !reflect.DeepEqual(f.calls, []string{"inspect"}) {
		t.Fatal(err, f.calls)
	}
}

func TestRepairConsentReinspectsHealthyService(t *testing.T) {
	f := &repairFake{observation: repairObservation{Owned: true, Unresponsive: true}}
	err := runRepairWithConsent(context.Background(), f, repairConsent{}, nil, func(context.Context, string) (bool, error) {
		f.observation = repairObservation{Owned: true}
		return true, nil
	})
	if err != nil || !reflect.DeepEqual(f.calls, []string{"inspect", "inspect", "ready"}) {
		t.Fatal(err, f.calls)
	}
}

func TestRepairConsentReplyBoundaries(t *testing.T) {
	for _, reply := range []string{`{}`, `{"consent":"network-recovery","approved":true}`, `{"consent":"disruption","approved":true,"command":"shell"}`, `{"consent":"disruption","approved":null}`, `{"consent":"disruption","approved":true} {}`} {
		if _, err := parseRepairConsent([]byte(reply), "disruption"); err == nil {
			t.Fatal("accepted", reply)
		}
	}
	for _, approved := range []string{"true", "false"} {
		got, err := parseRepairConsent([]byte(`{"consent":"disruption","approved":`+approved+`}`), "disruption")
		if err != nil || got != (approved == "true") {
			t.Fatal(got, err)
		}
	}
}
