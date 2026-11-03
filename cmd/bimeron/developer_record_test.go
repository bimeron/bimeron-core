package main

import (
	"bimeron/internal/control"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDeveloperIdentityRejectsReuse(t *testing.T) {
	a := developerRecord{Version: 1, PID: 42, Owner: "owner", Session: 1, Created: "first", Image: "image", SHA256: strings.Repeat("ab", 32)}
	for _, mutate := range []func(*developerRecord){
		func(r *developerRecord) { r.PID++ }, func(r *developerRecord) { r.Owner = "other" },
		func(r *developerRecord) { r.Session++ }, func(r *developerRecord) { r.Created = "reused" },
		func(r *developerRecord) { r.SHA256 = strings.Repeat("cd", 32) },
	} {
		b := a
		mutate(&b)
		if sameDeveloper(a, b) {
			t.Fatal("accepted mismatched process")
		}
	}
	for _, data := range []string{`{"version":1}`, `{}`, `null`} {
		if _, err := parseDeveloperRecord([]byte(data)); err == nil {
			t.Fatal("accepted legacy record")
		}
	}
	data, _ := json.Marshal(a)
	if _, err := parseDeveloperRecord(data); err != nil {
		t.Fatal(err)
	}
}

type developerRepairFake struct{ repairFake }

func (f *developerRepairFake) DeveloperPending(context.Context) (bool, error) { return true, nil }
func (f *developerRepairFake) StopDeveloper(context.Context) error            { return f.call("developer-stop") }
func TestDeveloperConsentAndCleanupGate(t *testing.T) {
	for _, approved := range []bool{false, true} {
		f := &developerRepairFake{repairFake{observation: repairObservation{Owned: true, Stopped: true}, fail: "developer-stop"}}
		err := runRepairWithConsent(context.Background(), f, repairConsent{}, nil, func(context.Context, string) (bool, error) { return approved, nil })
		if err == nil {
			t.Fatal("expected refusal or cleanup failure")
		}
		if (!approved && len(f.calls) != 0) || (approved && (len(f.calls) != 1 || f.calls[0] != "developer-stop")) {
			t.Fatalf("unsafe restoration: %v", f.calls)
		}
	}
}

func TestDeveloperCleanupRequiresDurableProof(t *testing.T) {
	for _, mode := range []string{"clean", "missing", "dirty", "changed", "endpoint", "no-exit"} {
		t.Run(mode, func(t *testing.T) {
			r := developerRecord{Version: 1, PID: 42, Owner: "owner", Created: "created", Image: "image", SHA256: strings.Repeat("ab", 32)}
			calls := 0
			dial := func(context.Context) (net.Conn, error) {
				if mode == "endpoint" {
					return nil, errors.New("peer rejected")
				}
				a, b := net.Pipe()
				go func() {
					defer b.Close()
					var req control.Request
					if json.NewDecoder(b).Decode(&req) != nil {
						return
					}
					response := control.Response{Version: control.Version, ID: req.ID, Instance: "instance"}
					response.Status.State = "disconnected"
					json.NewEncoder(b).Encode(response)
				}()
				calls++
				return a, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			read := func() ([]byte, error) {
				if mode == "missing" {
					return nil, errors.New("missing")
				}
				clean := r
				clean.Clean = mode != "dirty"
				if mode == "changed" {
					clean.Created = "other"
				}
				return json.Marshal(clean)
			}
			err := stopRecordedDeveloper(ctx, r, dial, func() bool { return mode != "no-exit" }, read)
			if (err == nil) != (mode == "clean") {
				t.Fatalf("unexpected result: %v", err)
			}
			if mode != "endpoint" && calls != 3 {
				t.Fatalf("calls=%d", calls)
			}
		})
	}
}
