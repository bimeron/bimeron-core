package core

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
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
type UpdateHold struct{ Path string }

type updateHoldRecord struct {
	Version   int       `json:"version"`
	ProfileID string    `json:"profile_id"`
	Time      time.Time `json:"time"`
}

// Write records profileID, replacing an earlier record.
func (h UpdateHold) Write(profileID string) error {
	if !validProfileID(profileID) {
		return fmt.Errorf("invalid profile id")
	}
	b, err := json.Marshal(updateHoldRecord{Version: 1, ProfileID: profileID, Time: time.Now().UTC()})
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
	f, err := os.Open(h.Path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return ""
	}
	var r updateHoldRecord
	if json.Unmarshal(b, &r) != nil || r.Version != 1 || !validProfileID(r.ProfileID) {
		return ""
	}
	return r.ProfileID
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
