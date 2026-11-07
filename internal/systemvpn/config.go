// Package systemvpn controls OS-owned IKEv2 tunnels without processing packets.
package systemvpn

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"bimeron/internal/problem"
)

// Config references a pre-provisioned, current-user Windows VPN profile.
// It contains no credentials. ServerName pins the expected DNS server identity.
type Config struct {
	WindowsProfile string
	ServerName     string
	KillSwitch     bool
}

var dnsLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// Validate returns a problem located at the [IKEv2] option. Messages equal the
// codes, which callers and status reporting already use verbatim.
func (c Config) Validate() error {
	if !utf8.ValidString(c.WindowsProfile) || strings.TrimSpace(c.WindowsProfile) != c.WindowsProfile || c.WindowsProfile == "" || len(utf16.Encode([]rune(c.WindowsProfile))) > 256 || strings.ContainsAny(c.WindowsProfile, `\/[]`) || strings.IndexFunc(c.WindowsProfile, unicode.IsControl) >= 0 {
		return problem.New("ikev2_invalid_windows_profile", "ikev2_invalid_windows_profile").In("IKEv2").On("WindowsProfile", c.WindowsProfile)
	}
	if len(c.ServerName) > 253 || !strings.Contains(c.ServerName, ".") {
		return problem.New("ikev2_server_name_requires_dns_name", "ikev2_server_name_requires_dns_name").In("IKEv2").On("ServerName", c.ServerName)
	}
	allNumeric := true
	for _, label := range strings.Split(c.ServerName, ".") {
		if !dnsLabel.MatchString(label) {
			return problem.New("ikev2_invalid_server_name", "ikev2_invalid_server_name").In("IKEv2").On("ServerName", c.ServerName)
		}
		if strings.IndexFunc(label, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			allNumeric = false
		}
	}
	if allNumeric {
		return problem.New("ikev2_server_name_requires_dns_name", "ikev2_server_name_requires_dns_name").In("IKEv2").On("ServerName", c.ServerName)
	}
	return nil
}
