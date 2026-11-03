package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// repairBackend is deliberately internal: no CLI may expose it until its
// platform adapter authenticates the peer and verifies payload signatures.
// Every method runs within the original privileged process.
type repairBackend interface {
	Inspect(context.Context) (repairObservation, error)
	Install(context.Context) error
	Stop(context.Context) error
	CleanupProven(context.Context) error
	Recover(context.Context) error
	Start(context.Context) error
	Ready(context.Context) error
	Rollback(context.Context) error
}
type repairObservation struct {
	Missing, Stopped, Owned, Unresponsive, CleanupRequired bool
	ReplacementRequired                                    bool
}
type repairConsent struct{ Disruption, NetworkRecovery bool }
type repairStage string

// runRepair performs one bounded transaction. The adapter owns identity checks,
// fresh mutation guards, protected staging and compatible hello/status checks.
// Failure never initiates another authorization or retries mutations.
func runRepair(ctx context.Context, b repairBackend, consent repairConsent, emit func(repairStage)) error {
	return runRepairWithConsent(ctx, b, consent, emit, nil)
}

func runRepairWithConsent(ctx context.Context, b repairBackend, consent repairConsent, emit func(repairStage), requestConsent func(context.Context, string) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	step := func(name repairStage, fn func(context.Context) error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if emit != nil {
			emit(name)
		}
		if err := fn(ctx); err != nil {
			return fmt.Errorf("repair %s: %w", name, err)
		}
		return ctx.Err()
	}
	var observation repairObservation
	if developer, ok := b.(interface {
		DeveloperPending(context.Context) (bool, error)
		StopDeveloper(context.Context) error
	}); ok {
		pending, err := developer.DeveloperPending(ctx)
		if err != nil {
			return err
		}
		if pending {
			if !consent.Disruption {
				if requestConsent == nil {
					return errors.New("repair disruption consent required")
				}
				approved, err := requestConsent(ctx, "disruption")
				if err != nil {
					return err
				}
				if !approved {
					return errors.New("repair consent denied")
				}
				consent.Disruption = true
			}
			if err := step("stop", developer.StopDeveloper); err != nil {
				return err
			}
		}
	}
	for {
		granted := false
		if err := step("inspect", func(ctx context.Context) (err error) { observation, err = b.Inspect(ctx); return }); err != nil {
			return err
		}
		if (observation.Unresponsive || observation.CleanupRequired) && !observation.Owned {
			return errors.New("repair mutation ownership unproven")
		}
		if observation.Missing && (observation.Stopped || observation.Unresponsive || observation.CleanupRequired || observation.ReplacementRequired) {
			return errors.New("contradictory repair observation")
		}
		if !observation.Missing && !observation.Owned {
			return errors.New("repair ownership unproven")
		}
		for _, required := range []struct {
			kind             string
			needed, approved bool
		}{
			{"disruption", observation.Unresponsive || (observation.ReplacementRequired && !observation.Stopped), consent.Disruption},
			{"network-recovery", observation.CleanupRequired, consent.NetworkRecovery},
		} {
			if !required.needed || required.approved {
				continue
			}
			if requestConsent == nil {
				return errors.New("repair " + required.kind + " consent required")
			}
			approved, err := requestConsent(ctx, required.kind)
			if err != nil {
				return err
			}
			if !approved {
				return errors.New("repair consent denied")
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if required.kind == "disruption" {
				consent.Disruption = true
			} else {
				consent.NetworkRecovery = true
			}
			granted = true
		}
		// Consent may take a minute. Rebuild the plan from fresh ownership/state;
		// a service that became healthy must not be stopped using stale evidence.
		if !granted {
			break
		}
	}
	if observation.Unresponsive {
		if err := step("stop", b.Stop); err != nil {
			return err
		}
		if err := step("confirm-cleanup", b.CleanupProven); err != nil {
			return err
		}
	}
	if observation.CleanupRequired {
		if err := step("recover", b.Recover); err != nil {
			return err
		}
		if err := step("confirm-cleanup", b.CleanupProven); err != nil {
			return err
		}
	}
	if observation.ReplacementRequired {
		if !observation.Owned {
			return errors.New("replacement ownership unproven")
		}
		replacement, ok := b.(interface{ Replace(context.Context) error })
		if !ok {
			return errors.New("component replacement unavailable")
		}
		if err := step("replace", replacement.Replace); err != nil {
			return err
		}
		if err := step("verify", b.Ready); err != nil {
			return err
		}
		if emit != nil {
			emit("ready")
		}
		return nil
	}
	installed := false
	rollback := func(cause error) error {
		if !installed {
			return cause
		}
		// Reserve a separate bounded cleanup window even if readiness exhausted the
		// transaction deadline. Rollback remains inside this same privileged process.
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer done()
		if emit != nil {
			emit("rollback")
		}
		return errors.Join(cause, b.Rollback(cleanup))
	}
	if observation.Missing {
		if err := step("install", func(ctx context.Context) error { err := b.Install(ctx); installed = err == nil; return err }); err != nil {
			return rollback(err)
		}
	}
	if observation.Missing || observation.Stopped || observation.Unresponsive || observation.CleanupRequired || observation.ReplacementRequired {
		if err := step("start", b.Start); err != nil {
			return rollback(err)
		}
	}
	if err := step("verify", b.Ready); err != nil {
		return rollback(err)
	}
	if emit != nil {
		emit("ready")
	}
	return nil
}

func waitRepairReady(ctx context.Context, probe func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var last error
	for ctx.Err() == nil {
		attempt, done := context.WithTimeout(ctx, 2*time.Second)
		last = probe(attempt)
		done()
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	return errors.Join(ctx.Err(), last)
}
