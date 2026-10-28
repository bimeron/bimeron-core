package systemvpn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

// ProfilePlan describes public settings only. Preparation never authenticates.
type ProfilePlan struct {
	Action         string   `json:"action"`
	WindowsProfile string   `json:"windows_profile"`
	ServerName     string   `json:"server_name"`
	Authentication string   `json:"authentication"`
	IPsec          string   `json:"ipsec"`
	IPv6Routes     []string `json:"ipv6_routes"`
	Credentials    string   `json:"credentials"`
	Trust          string   `json:"trust"`
}

type profileRecord struct {
	Version  int    `json:"version"`
	Name     string `json:"name"`
	Server   string `json:"server"`
	Snapshot string `json:"public_settings,omitempty"`
}

func validatePreparationConfig(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	// Cmdlet Name parameters must never interpret a profile as a wildcard.
	if strings.ContainsAny(cfg.WindowsProfile, "*?`") {
		return errors.New("ikev2_profile_wildcard_name_not_supported")
	}
	return nil
}

// A missing snapshot is an interrupted transaction, never proof of ownership.
func checkProfileRecord(record *profileRecord, cfg Config, snapshot string) error {
	if record == nil {
		if snapshot != "" {
			return errors.New("ikev2_profile_name_not_owned")
		}
		return nil
	}
	if record.Version != 1 || !strings.EqualFold(record.Name, cfg.WindowsProfile) || !strings.EqualFold(record.Server, cfg.ServerName) {
		return errors.New("ikev2_profile_manifest_conflict")
	}
	if record.Snapshot == "" {
		return errors.New("ikev2_profile_incomplete_transaction_manual_review_required")
	}
	if snapshot != record.Snapshot {
		return errors.New("ikev2_owned_profile_modified_or_missing")
	}
	return nil
}

func profileKey(name string) string {
	h := sha256.Sum256([]byte(strings.ToLower(name)))
	return hex.EncodeToString(h[:])
}

func readProfileRecord(path string) (*profileRecord, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("ikev2_profile_manifest_read_failed")
	}
	var record profileRecord
	if json.Unmarshal(b, &record) != nil {
		return nil, errors.New("ikev2_profile_manifest_invalid")
	}
	return &record, nil
}

func newProfilePlan(cfg Config) ProfilePlan {
	return ProfilePlan{Action: "create", WindowsProfile: cfg.WindowsProfile, ServerName: cfg.ServerName,
		Authentication: "IKEv2 only; EAP-MSCHAPv2; no automatic redial",
		IPsec:          "IKE AES256/SHA256/DH14; ESP AES256/SHA256; no PFS",
		IPv6Routes:     []string{"::/1", "8000::/1"},
		Credentials:    "Authenticate and save credentials in Windows; preparation does not read or write credentials.",
		Trust:          "Administrator must provision server CA trust; Windows certificate name/EKU validation remains enabled. Preparation does not install certificates or DNS/WFP policy."}
}
