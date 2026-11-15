//go:build windows

package main

import (
	"context"
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func TestStoppedWindowsRepairFirstSession(t *testing.T) {
	for _, tc := range []struct {
		name              string
		code              uint32
		pending, recovery bool
	}{
		{"killed without markers", uint32(windows.ERROR_PROCESS_ABORTED), false, true},
		{"killed with markers", uint32(windows.ERROR_PROCESS_ABORTED), true, true},
		{"clean with markers", 0, true, true},
		{"clean", 0, false, false},
		{"never started", uint32(windows.ERROR_SERVICE_NEVER_STARTED), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observation, err := stoppedWindowsRepairObservation(svc.Status{State: svc.Stopped, Win32ExitCode: tc.code}, tc.pending, false)
			if err != nil || observation.CleanupRequired != tc.recovery {
				t.Fatalf("observation %+v: %v", observation, err)
			}
			f := &repairFake{observation: observation}
			if err := runRepair(context.Background(), f, repairConsent{NetworkRecovery: true}, nil); err != nil {
				t.Fatal(err)
			}
			want := []string{"inspect", "start", "ready"}
			if tc.recovery {
				want = []string{"inspect", "recover", "cleanup", "start", "ready"}
			}
			if !reflect.DeepEqual(f.calls, want) {
				t.Fatal(f.calls)
			}
			if tc.recovery {
				for _, failure := range []string{"recover", "cleanup"} {
					f := &repairFake{observation: observation, fail: failure}
					if runRepair(context.Background(), f, repairConsent{NetworkRecovery: true}, nil) == nil {
						t.Fatal("failure ignored")
					}
					for _, call := range f.calls {
						if call == "start" {
							t.Fatal("started after failure")
						}
					}
				}
				f := &repairFake{observation: observation}
				if runRepair(context.Background(), f, repairConsent{}, nil) == nil || len(f.calls) != 1 {
					t.Fatal("consent bypass")
				}
			}
		})
	}
	for _, status := range []svc.Status{{State: svc.Running}, {State: svc.Stopped, ProcessId: 123}} {
		if _, err := stoppedWindowsRepairObservation(status, false, false); err == nil {
			t.Fatal("exit proof bypass")
		}
	}
	observation, err := stoppedWindowsRepairObservation(svc.Status{State: svc.Stopped}, true, true)
	if err != nil || !observation.ReplacementRequired || !observation.Stopped || !observation.CleanupRequired {
		t.Fatalf("lost stopped replacement plan: %+v %v", observation, err)
	}
	f := &repairReplacementFake{repairFake{observation: observation}}
	if err := runRepair(context.Background(), f, repairConsent{NetworkRecovery: true}, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.calls, []string{"inspect", "recover", "cleanup", "replace", "ready"}) {
		t.Fatal(f.calls)
	}
}
