package control

import (
	"context"
	"strings"
	"testing"
)

func TestHandshakeIdentityAndCorrelation(t *testing.T) {
	s := NewServer(&fakeEngine{})
	a := s.dispatch(context.Background(), Request{Version: Version, Command: "hello", ID: "gui-1"})
	if a.Error != "" || a.ID != "gui-1" || len(a.Instance) != 32 || a.Capabilities == nil || a.Core == nil || a.Core.Version == "" {
		t.Fatal(a)
	}
	next := s.dispatch(context.Background(), Request{Version: Version, Command: "status"})
	if next.Instance != a.Instance {
		t.Fatal("unstable instance")
	}
	if NewServer(&fakeEngine{}).instance == a.Instance {
		t.Fatal("duplicate instance")
	}
	if got := s.dispatch(context.Background(), Request{Version: Version, Command: "hello", ID: strings.Repeat("x", 65)}); got.Error != "invalid_request" {
		t.Fatal(got)
	}
	if got := s.dispatch(context.Background(), Request{Version: Version + 1, Command: "hello"}); got.Error != "unsupported_protocol" {
		t.Fatal(got)
	}
}
