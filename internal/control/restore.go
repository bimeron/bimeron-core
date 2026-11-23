package control

import (
	"encoding/hex"
	"encoding/json"
	"strings"
)

type RestoreProof struct {
	Version      int    `json:"version"`
	Operation    string `json:"operation_id"`
	Outcome      string `json:"outcome"`
	CurrentState string `json:"current_state"`
	Code         string `json:"code"`
}

func restoreID(id string) bool {
	if len(id) != 32 || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
func strictRestoreKeys(line []byte, keys ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(line, &fields) != nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		if len(fields[key]) == 0 {
			return false
		}
	}
	return true
}
