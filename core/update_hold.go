package core

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"time"
)

// ResidualUpdate is Status.ResidualReason for kill switch protection that a
// service kept on purpose across a client-requested update (ADR 0041).
const ResidualUpdate = "update"

// UpdateHold is the record of the profile whose kill switch protection a
// service kept across an update. The stopping service writes it; the next
// service reads it to report the held profile with the residual protection,
// so a client can start that profile again. Path must be in a directory that
// only SYSTEM and administrators can write.
type UpdateHold struct {
	Path             string
	filterGeneration func() (string, error)
}

func (h UpdateHold) generation() (string, error) {
	if h.filterGeneration != nil {
		return h.filterGeneration()
	}
	return installedFilterGeneration()
}

type updateHoldRecord struct {
	Transaction string    `json:"transaction,omitempty"`
	Version     int       `json:"version"`
	Generation  string    `json:"filter_generation"`
	ProfileID   string    `json:"profile_id"`
	Time        time.Time `json:"time"`
}

// Write records profileID, replacing an earlier record.
func (h UpdateHold) Write(profileID string) error {
	return h.WriteTransaction(profileID, "")
}

func (h UpdateHold) WriteTransaction(profileID, transaction string) error {
	if !validProfileID(profileID) {
		return fmt.Errorf("invalid profile id")
	}
	generation, err := h.generation()
	if err != nil {
		return err
	}
	if generation == "" {
		return errors.New("missing filter generation")
	}
	return h.writeRecord(updateHoldRecord{Version: 2, Generation: generation, ProfileID: profileID, Transaction: transaction, Time: time.Now().UTC()})
}

func (h UpdateHold) writeRecord(record updateHoldRecord) error {
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	staged := h.Path + ".new"
	if err := writeHoldFile(staged, b); err != nil {
		return err
	}
	return os.Rename(staged, h.Path)
}

// Read returns the recorded profile_id, or "" without a valid record.
func (h UpdateHold) Read() string {
	return h.readRecord().ProfileID
}

// TransactionProfile checks both the privileged marker and the installed filters.
func (h UpdateHold) TransactionProfile(transaction string) string {
	r := h.readRecord()
	if transaction == "" || r.Transaction != transaction {
		return ""
	}
	return r.ProfileID
}

// Renew captures the exact verified residual at prepare. A subsequent stop
// can relabel only that same record and filter generation.
func (h UpdateHold) Renew(profile string) func(string) error {
	previous := h.readRecord()
	return func(transaction string) error {
		if previous.ProfileID == "" || previous.ProfileID != profile || previous != h.readRecord() {
			return errors.New("update residual changed")
		}
		previous.Transaction = transaction
		return h.writeRecord(previous)
	}
}

func (h UpdateHold) readRecord() updateHoldRecord {
	f, err := os.Open(h.Path)
	if err != nil {
		return updateHoldRecord{}
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return updateHoldRecord{}
	}
	var r updateHoldRecord
	if json.Unmarshal(b, &r) != nil || r.Version != 2 || r.Generation == "" || !validProfileID(r.ProfileID) {
		return updateHoldRecord{}
	}
	generation, err := h.generation()
	if err != nil || generation != r.Generation {
		return updateHoldRecord{}
	}
	return r
}

// Finish publishes the SCM stop outcome after the engine has finished cleanup.
func (h UpdateHold) Finish(transaction, profile string) error {
	if transaction == "" || profile != "" && h.TransactionProfile(transaction) != profile {
		return errors.New("update stop protection unconfirmed")
	}
	receipt := UpdateHold{Path: h.Path + ".stop"}
	return receipt.writeRecord(updateHoldRecord{Transaction: transaction, ProfileID: profile})
}

func (h UpdateHold) StopOutcome(transaction string) (string, error) {
	b, err := os.ReadFile(h.Path + ".stop")
	if err != nil {
		return "", err
	}
	var r updateHoldRecord
	if json.Unmarshal(b, &r) != nil || transaction == "" || r.Transaction != transaction ||
		r.ProfileID != "" && (!validProfileID(r.ProfileID) || h.TransactionProfile(transaction) != r.ProfileID) {
		return "", errors.New("update stop outcome unconfirmed")
	}
	return r.ProfileID, nil
}

// Clear removes the record; a missing record is not an error.
func (h UpdateHold) Clear() error {
	if err := os.Remove(h.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// HasUpdateHold reports the failed cleanup state of a held update profile.
func (s Status) HasUpdateHold() bool {
	return s.State == Failed && s.KillSwitch == KillSwitchResidual && s.ResidualReason == ResidualUpdate &&
		validProfileID(s.ResidualProfile) && s.LastError == "cleanup_failed_run_recover"
}

// validProfileID accepts the lowercase hex SHA-256 form of Session.ProfileID.
func validProfileID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == id
}

// ErrUpdateResumeConflict means the held protection could not be claimed.
var ErrUpdateResumeConflict = errors.New("update_resume_conflict")

type updateResume struct {
	hold       UpdateHold
	profile    string
	generation string
}

func (e *Engine) SupportsUpdateResume() bool {
	return runtime.GOOS == "windows" && e.opts.UpdateHold != nil && e.opts.ResidualProtection
}

// ResumeUpdate starts the exact protected profile if its retained generation
// still exists when the Windows session lock is acquired.
func (e *Engine) ResumeUpdate(ctx context.Context, cfg SessionConfig, profile, generation string) error {
	if !e.SupportsUpdateResume() || !validProfileID(profile) || !validProfileID(generation) ||
		cfg.ProfileID != profile || !cfg.KillSwitch || cfg.Mode != "vpn" || cfg.IKEv2 != nil {
		return ErrUpdateResumeConflict
	}
	cfg.updateResume = &updateResume{hold: *e.opts.UpdateHold, profile: profile, generation: generation}
	return e.Start(ctx, cfg)
}

func (r *updateResume) matches() bool {
	record := r.hold.readRecord()
	return record.ProfileID == r.profile && record.Generation == r.generation
}
