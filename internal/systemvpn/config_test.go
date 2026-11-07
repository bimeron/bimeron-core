package systemvpn

import (
	"testing"

	"bimeron/internal/problem"
)

func TestConfigProblems(t *testing.T) {
	for _, tc := range []struct {
		profile, server string
		code, field     string
		value           problem.Value
	}{
		{"", "vpn.example.com", "ikev2_invalid_windows_profile", "WindowsProfile", problem.Absent},
		{"Work/VPN", "vpn.example.com", "ikev2_invalid_windows_profile", "WindowsProfile", problem.Present},
		{"Work", "", "ikev2_server_name_requires_dns_name", "ServerName", problem.Absent},
		{"Work", "10.0.0.1", "ikev2_server_name_requires_dns_name", "ServerName", problem.Present},
		{"Work", "vpn..example.com", "ikev2_invalid_server_name", "ServerName", problem.Present},
	} {
		err := Config{WindowsProfile: tc.profile, ServerName: tc.server}.Validate()
		p, ok := problem.As(err)
		if !ok || err.Error() != tc.code || p.Code != tc.code || p.Section != "IKEv2" || p.Field != tc.field || p.Value != tc.value || p.Args != nil {
			t.Errorf("%q/%q: problem = %+v (%v)", tc.profile, tc.server, p, err)
			continue
		}
		if !problem.Known(p.Code) {
			t.Errorf("code %q has no catalog entry", p.Code)
		}
	}
}
