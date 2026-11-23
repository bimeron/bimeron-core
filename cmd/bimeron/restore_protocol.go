package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

type restoreTarget struct {
	Version string `json:"version"`
	Arch    string `json:"arch"`
	SHA256  string `json:"sha256"`
}
type heldRestoreRequest struct {
	Version    int           `json:"version"`
	Command    string        `json:"command"`
	Operation  string        `json:"operation_id"`
	Instance   string        `json:"expected_instance"`
	Profile    string        `json:"profile_id"`
	Generation string        `json:"filter_generation"`
	Target     restoreTarget `json:"target"`
	Disruption bool          `json:"disruption"`
	Recovery   bool          `json:"network_recovery"`
}

func restoreHex(s string, n int) bool {
	if len(s) != n || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Decode exact, unique JSON member names. Go struct decoding alone accepts
// case-insensitive keys and repeated members with last-value-wins semantics.
func restoreObject(data []byte, keys ...string) (map[string]json.RawMessage, error) {
	bad := errors.New("invalid restore object")
	allowed := make(map[string]bool, len(keys))
	for _, k := range keys {
		allowed[k] = true
	}
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, bad
	}
	out := make(map[string]json.RawMessage, len(keys))
	for d.More() {
		t, err = d.Token()
		k, ok := t.(string)
		if err != nil || !ok || !allowed[k] {
			return nil, bad
		}
		delete(allowed, k)
		var raw json.RawMessage
		if err = d.Decode(&raw); err != nil || bytes.Equal(raw, []byte("null")) {
			return nil, bad
		}
		out[k] = raw
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') || len(allowed) != 0 {
		return nil, bad
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, bad
	}
	return out, nil
}
func parseHeldRestore(data []byte) (heldRestoreRequest, error) {
	var r heldRestoreRequest
	if len(data) > 1024 {
		return r, errors.New("restore request too large")
	}
	fields, err := restoreObject(data, "version", "command", "operation_id", "expected_instance", "profile_id", "filter_generation", "target", "disruption", "network_recovery")
	if err != nil {
		return r, err
	}
	if _, err = restoreObject(fields["target"], "version", "arch", "sha256"); err != nil {
		return r, err
	}
	if err = json.Unmarshal(data, &r); err != nil {
		return r, err
	}
	if r.Version != 2 || r.Command != "restore_held" || !restoreHex(r.Operation, 32) || !restoreHex(r.Instance, 32) || !restoreHex(r.Profile, 64) || !restoreHex(r.Generation, 64) || !restoreHex(r.Target.SHA256, 64) || r.Target.Arch != "amd64" || r.Target.Version == "" || len(r.Target.Version) > 96 {
		return r, errors.New("invalid restore identity")
	}
	return r, nil
}
