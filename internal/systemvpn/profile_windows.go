//go:build windows

package systemvpn

import (
	"bimeron/internal/windowsnet"
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed profile_windows.ps1
var profileScript string

func profileOperation(action string, cfg Config, expected string) (string, error) {
	payload, _ := json.Marshal(map[string]string{"action": action, "name": cfg.WindowsProfile, "server": cfg.ServerName, "expected": expected})
	units := utf16.Encode([]rune(profileScript))
	encoded := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(encoded[2*i:], u)
	}
	root, err := windows.GetWindowsDirectory()
	if err != nil {
		return "", errors.New("ikev2_windows_directory_unavailable")
	}
	// Mutations are intentionally synchronous: cancellation must not kill the
	// child halfway through rollback. A crash leaves the pending journal intact.
	cmd := exec.Command(filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.Output()
	if err != nil {
		return "", errors.New("ikev2_profile_windows_operation_failed")
	}
	return strings.TrimSpace(string(out)), nil
}

func profileSnapshot(d *windowsDriver, cfg Config) (string, string, error) {
	public, err := profileOperation("inspect", cfg, "")
	if err != nil || public == "" {
		return "", "", err
	}
	e, err := d.entry(cfg)
	if err != nil {
		return "", "", err
	}
	// RASENTRY has no credentials. Store exact public settings, including GUID,
	// hooks and certificate flags, so a same-name replacement is never adopted.
	entry, _ := json.Marshal(e)
	return string(entry) + "\n" + public, public, nil
}

func normalizeCreatedProfile(d *windowsDriver, cfg Config, guid string) error {
	if err := noRASConnections(); err != nil {
		return err
	}
	e, err := d.entry(cfg)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.Trim(e.GUID.String(), "{}"), strings.Trim(guid, "{}")) {
		return errors.New("ikev2_profile_identity_changed")
	}
	e.Options = (e.Options | rasRequireEAP | 0x10 | 0x1000) &^ (rasOtherAuth | rasUnsupportedOptions)
	e.Options2 = (e.Options2 | 0x2000) &^ rasUnsafeOptions2
	e.NetProtocols, e.EncryptionType, e.CustomAuthKey, e.RedialCount = 0xc, 1, 26, 0
	if err := validateEntry(e, cfg); err != nil {
		return err
	}
	book, _ := windows.UTF16PtrFromString(d.phonebook)
	name, _ := windows.UTF16PtrFromString(cfg.WindowsProfile)
	code, _, _ := rasDLL.NewProc("RasSetEntryPropertiesW").Call(uintptr(unsafe.Pointer(book)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&e)), unsafe.Sizeof(e), 0, 0)
	if code != 0 {
		return rasError(uint32(code))
	}
	e, err = d.entry(cfg)
	if err != nil {
		return err
	}
	return validateEntry(e, cfg)
}

func writeProfileRecord(path string, record profileRecord, exclusive bool) error {
	data, _ := json.MarshalIndent(record, "", "  ")
	if exclusive {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".profile-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, path)
}

// PrepareProfile previews by default, or explicitly creates/removes an owned
// current-user profile. It never reads saved credentials or installs trust.
func PrepareProfile(cfg Config, apply, remove bool) (ProfilePlan, error) {
	return prepareProfile(cfg, apply, remove, "")
}

// PrepareProfileReviewed requires the state token returned by preview and
// rechecks it under the same lock as the mutation. It never adopts a journal.
func PrepareProfileReviewed(cfg Config, remove bool, expected string) (ProfilePlan, error) {
	if len(expected) != 64 {
		return ProfilePlan{}, errors.New("ikev2_profile_preview_required")
	}
	return prepareProfile(cfg, !remove, remove, expected)
}

func prepareProfile(cfg Config, apply, remove bool, expected string) (ProfilePlan, error) {
	plan := newProfilePlan(cfg)
	if err := validatePreparationConfig(cfg); err != nil {
		return plan, err
	}
	if apply && remove {
		return plan, errors.New("ikev2_profile_conflicting_actions")
	}
	if apply || remove {
		unlock, err := windowsnet.Acquire()
		if err != nil {
			return plan, err
		}
		defer unlock()
		if err := noRASConnections(); err != nil {
			return plan, err
		}
	}
	appData, err := windows.KnownFolderPath(windows.FOLDERID_RoamingAppData, 0)
	if err != nil {
		return plan, err
	}
	local, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		return plan, err
	}
	d := &windowsDriver{phonebook: filepath.Join(appData, "Microsoft", "Network", "Connections", "Pbk", "rasphone.pbk")}
	path := filepath.Join(local, "Bimeron", "ikev2-profiles", profileKey(cfg.WindowsProfile)+".json")
	snapshot, public, err := profileSnapshot(d, cfg)
	if err != nil {
		return plan, err
	}
	record, err := readProfileRecord(path)
	if err != nil {
		return plan, err
	}
	if err := checkProfileRecord(record, cfg, snapshot); err != nil {
		return plan, err
	}
	plan.StateToken = profileStateToken(cfg, snapshot, record)
	if expected != "" && expected != plan.StateToken {
		return plan, errors.New("ikev2_profile_preview_changed")
	}
	if record != nil {
		plan.Action = "unchanged"
	}
	if remove {
		if record == nil {
			return plan, errors.New("ikev2_profile_not_owned")
		}
		// inspect also refuses any active RAS session, including a stale owner.
		if err := d.inspect(cfg); err != nil {
			return plan, err
		}
		if _, err := profileOperation("remove", cfg, public); err != nil {
			return plan, err
		}
		if err := os.Remove(path); err != nil {
			return plan, errors.New("ikev2_profile_removed_manifest_cleanup_failed")
		}
		plan.Action = "removed"
		return plan, nil
	}
	if !apply || record != nil {
		return plan, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return plan, err
	}
	pending := profileRecord{Version: 1, Name: cfg.WindowsProfile, Server: cfg.ServerName}
	if err := writeProfileRecord(path, pending, true); err != nil {
		return plan, errors.New("ikev2_profile_journal_write_failed")
	}
	createdGUID, createErr := profileOperation("create", cfg, "")
	created := createErr == nil && createdGUID != ""
	if createErr == nil && !created {
		createErr = errors.New("ikev2_created_profile_identity_missing")
	}
	if createErr == nil {
		createErr = normalizeCreatedProfile(d, cfg, createdGUID)
	}
	snapshot, public, err = profileSnapshot(d, cfg)
	if createErr == nil {
		createErr = err
	}
	if createErr == nil && snapshot == "" {
		createErr = errors.New("ikev2_created_profile_missing")
	}
	if createErr == nil {
		e, entryErr := d.entry(cfg)
		if entryErr != nil {
			createErr = entryErr
		} else if !strings.EqualFold(strings.Trim(e.GUID.String(), "{}"), strings.Trim(createdGUID, "{}")) {
			createErr = errors.New("ikev2_profile_identity_changed")
		} else {
			createErr = d.inspect(cfg)
		}
	}
	if createErr == nil {
		pending.Snapshot = snapshot
		createErr = writeProfileRecord(path, pending, false)
	}
	if createErr != nil {
		// The script rolls back partial cmdlet creation. Once creation completed,
		// remove only the exact inactive public settings observed by this call.
		if err == nil && snapshot != "" {
			e, entryErr := d.entry(cfg)
			if !created || entryErr != nil || !strings.EqualFold(strings.Trim(e.GUID.String(), "{}"), strings.Trim(createdGUID, "{}")) {
				return plan, errors.New("ikev2_profile_rollback_incomplete_manual_review_required")
			}
			_, err = profileOperation("remove", cfg, public)
		}
		if err != nil {
			return plan, errors.New("ikev2_profile_rollback_incomplete_manual_review_required")
		}
		if err := os.Remove(path); err != nil {
			return plan, errors.New("ikev2_profile_rollback_manifest_cleanup_failed")
		}
		return plan, errors.New("ikev2_profile_creation_failed_rolled_back")
	}
	plan.Action = "created"
	return plan, nil
}
