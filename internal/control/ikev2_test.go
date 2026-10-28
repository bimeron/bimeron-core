package control

import (
	"context"
	"path/filepath"
	"testing"

	"bimeron/core"
)

func TestDaemonCannotUseForegroundIKEv2Credentials(t *testing.T) {
	e := &fakeEngine{}
	s := NewServer(e)
	s.load = func(string) (core.SessionConfig, error) {
		return core.SessionConfig{Mode: "vpn", IKEv2: &core.IKEv2Config{WindowsProfile: "Corporate VPN", ServerName: "vpn.example.com"}}, nil
	}
	path, _ := filepath.Abs("profile.conf")
	a := s.dispatch(context.Background(), Request{Version: Version, Command: "start", Config: path})
	if a.Error != "ikev2_requires_foreground_user_session" || e.session != nil {
		t.Fatal("daemon used credentials from wrong account", a)
	}
	// The early rejection must release the command lock.
	if a := s.dispatch(context.Background(), Request{Version: Version, Command: "stop"}); a.Error != "" {
		t.Fatal(a)
	}
}
