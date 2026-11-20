package problem

import (
	"slices"
	"testing"
)

// GUIs mask values of these fields next to problems.
func TestListenPasswordIsSecret(t *testing.T) {
	if !slices.Contains(MustLoad().SecretFields, "ListenPassword") {
		t.Fatal("ListenPassword is not a secret field")
	}
}
