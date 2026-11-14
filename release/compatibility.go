// Package release provides the compatibility policy embedded in this build.
package release

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed compatibility.json
var compatibilityJSON string

// Compatibility is the release policy shared by signed manifests and brokers.
type Compatibility struct {
	Schema   int    `json:"schema"`
	Reviewed bool   `json:"gui_reviewed"`
	Min      string `json:"gui_min"`
	Max      string `json:"gui_max_exclusive"`
	IPCMin   int    `json:"ipc_min"`
	IPCMax   int    `json:"ipc_max"`
	Profile  int    `json:"profile_format"`
}

// ReviewedCompatibility returns a copy of the build's reviewed policy. Invalid
// or unreviewed embedded metadata fails closed without requiring runtime files.
func ReviewedCompatibility() (Compatibility, error) {
	var c Compatibility
	if err := json.Unmarshal([]byte(compatibilityJSON), &c); err != nil {
		return c, err
	}
	if c.Schema != 1 || !c.Reviewed || c.Min == "" || c.Max == "" || c.Min == c.Max || c.IPCMin < 1 || c.IPCMax < c.IPCMin || c.Profile < 1 {
		return Compatibility{}, fmt.Errorf("embedded release compatibility is not reviewed or invalid")
	}
	return c, nil
}
