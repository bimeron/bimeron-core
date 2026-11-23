package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHeldRestoreStrictWire(t *testing.T) {
	r := heldRestoreRequest{Version: 2, Command: "restore_held", Operation: strings.Repeat("a", 32), Instance: strings.Repeat("b", 32), Profile: strings.Repeat("c", 64), Generation: strings.Repeat("d", 64), Target: restoreTarget{"lab", "amd64", strings.Repeat("e", 64)}, Disruption: true, Recovery: true}
	b, _ := json.Marshal(r)
	if got, err := parseHeldRestore(b); err != nil || got != r {
		t.Fatalf("round trip: %v", err)
	}
	for _, bad := range []string{strings.Replace(string(b), "operation_id", "Operation_ID", 1), strings.Replace(string(b), "{", "{\"version\":2,", 1), strings.Replace(string(b), "\"arch\":", "\"arch\":\"amd64\",\"arch\":", 1), strings.Replace(string(b), "true", "null", 1), strings.Replace(string(b), r.Generation, strings.ToUpper(r.Generation), 1), string(b) + "{}"} {
		if _, err := parseHeldRestore([]byte(bad)); err == nil {
			t.Fatal("accepted malformed guarded restore")
		}
	}
}
