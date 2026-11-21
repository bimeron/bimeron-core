package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// -keep-kill-switch is an optional flag of service update.
func TestUpdateExpectationKeepKillSwitch(t *testing.T) {
	source, err := filepath.Abs("bimeron-update")
	if err != nil {
		t.Fatal(err)
	}
	base := []string{"-source", source, "-version", "0.4.0", "-sha256", strings.Repeat("a", 64)}
	e, err := parseUpdateExpectation(base)
	if err != nil || e.keepKillSwitch {
		t.Fatal(e, err)
	}
	e, err = parseUpdateExpectation(append([]string{"-keep-kill-switch"}, base...))
	if err != nil || !e.keepKillSwitch || e.version != "0.4.0" || e.source != source {
		t.Fatal(e, err)
	}
}
