package main

import (
	"errors"
	"strings"
	"testing"
)

func TestRepairFailureDoesNotExposeRawDiagnostics(t *testing.T) {
	if got := repairFailureCode(errors.New("secret-token=PRIVATE")); got != "operation-failed" {
		t.Fatal(got)
	}
	if got := repairFailureCode(errors.New("repair stop: service cleanup unconfirmed")); got != "cleanup-unconfirmed" {
		t.Fatal(got)
	}
}

func TestRepairRequestBoundary(t *testing.T) {
	for _, input := range []string{`{}`, `null`, `{"version":2}`, `{"version":1,"command":"shell"}`, `{"version":1,"source":"C:/writable.exe"}`, `{"version":1} {"version":1}`, strings.Repeat(" ", 1025), `{"version":1,"disruption":"true"}`} {
		if _, err := parseRepairRequest([]byte(input)); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
	request, err := parseRepairRequest([]byte("{\"version\":1,\"disruption\":true,\"networkRecovery\":false}\n"))
	if err != nil || !request.Disruption || request.NetworkRecovery {
		t.Fatal(request, err)
	}
}
func TestRepairSessionArgumentBoundary(t *testing.T) {
	for _, args := range [][]string{nil, {"../path", "1"}, {strings.Repeat("a", 32), "0"}, {strings.Repeat("a", 32), "-1"}, {strings.Repeat("a", 32), "4294967296"}, {strings.Repeat("a", 32), "1", "shell"}} {
		if err := repairSessionCommand(args); err == nil {
			t.Fatal("accepted", args)
		}
	}
}
