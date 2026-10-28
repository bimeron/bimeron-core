// Package systemvpn controls OS-owned IKEv2 tunnels without processing packets.
package systemvpn

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Config references a pre-provisioned, current-user Windows VPN profile.
// It contains no credentials. ServerName pins the expected DNS server identity.
type Config struct {
	WindowsProfile string
	ServerName     string
}

var dnsLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func (c Config) Validate() error {
	if !utf8.ValidString(c.WindowsProfile) || strings.TrimSpace(c.WindowsProfile) != c.WindowsProfile || c.WindowsProfile == "" || len(utf16.Encode([]rune(c.WindowsProfile))) > 256 || strings.ContainsAny(c.WindowsProfile, `\/[]`) || strings.IndexFunc(c.WindowsProfile, unicode.IsControl) >= 0 {
		return errors.New("ikev2_invalid_windows_profile")
	}
	if len(c.ServerName) > 253 || !strings.Contains(c.ServerName, ".") {
		return errors.New("ikev2_server_name_requires_dns_name")
	}
	allNumeric := true
	for _, label := range strings.Split(c.ServerName, ".") {
		if !dnsLabel.MatchString(label) {
			return errors.New("ikev2_invalid_server_name")
		}
		if strings.IndexFunc(label, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			allNumeric = false
		}
	}
	if allNumeric {
		return errors.New("ikev2_server_name_requires_dns_name")
	}
	return nil
}
