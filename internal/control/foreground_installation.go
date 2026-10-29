package control

import (
	"encoding/json"
	"errors"
)

const ForegroundInstallationFile = "bimeron-foreground.json"

var errForegroundInstallation = errors.New("foreground_installation_policy_rejected")

type foregroundInstallation struct {
	Schema       int    `json:"schema"`
	Installation string `json:"installation"`
	GUIHash      string `json:"gui_sha256"`
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func parseForegroundInstallation(data []byte) (foregroundInstallation, error) {
	var policy foregroundInstallation
	if len(data) > 4096 || !strictForegroundJSON(data) {
		return policy, errForegroundInstallation
	}
	d := json.NewDecoder(bytesReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&policy) != nil || policy.Schema != 1 || !lowerHex(policy.Installation, 32) || !lowerHex(policy.GUIHash, 64) {
		return foregroundInstallation{}, errForegroundInstallation
	}
	return policy, nil
}
