package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

// SessionInfo describes the most recently accepted Start, never credentials.
// KillSwitchRequested is configuration intent, not evidence of installed filters.
type SessionInfo struct {
	Backend             string `json:"backend,omitempty"`
	StatsUnavailable    bool   `json:"stats_unavailable,omitempty"`
	ID                  string `json:"id"`
	ProfileID           string `json:"profile_id,omitempty"`
	ProfileName         string `json:"profile_name,omitempty"`
	Active              bool   `json:"active"`
	Mode                string `json:"mode"`
	IPv6                string `json:"ipv6"`
	KillSwitchRequested bool   `json:"kill_switch_requested"`
	ServerTCP           string `json:"server_tcp,omitempty"`
	ServerUDP           string `json:"server_udp,omitempty"`
	ServerTCPName       string `json:"server_tcp_name,omitempty"`
	ServerUDPName       string `json:"server_udp_name,omitempty"`
}

type sessionEndpoints struct {
	tcp, udp, tcpName, udpName string
}

func newSessionInfo(c SessionConfig) (*SessionInfo, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("session_identity_failed")
	}
	profileID := ""
	if bytes, err := hex.DecodeString(c.ProfileID); err == nil && len(bytes) == 32 {
		profileID = strings.ToLower(c.ProfileID)
	}
	name := []rune(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, c.ProfileName))
	if len(name) > 128 {
		name = name[:128]
	}
	ipv6 := "enable"
	if c.IKEv2 != nil {
		return &SessionInfo{ID: hex.EncodeToString(id[:]), ProfileID: profileID, ProfileName: string(name), Active: true, Mode: c.Mode, IPv6: "system", Backend: "ikev2", StatsUnavailable: true}, nil
	}
	if c.DisableIPv6 {
		ipv6 = "disable"
	}
	return &SessionInfo{ID: hex.EncodeToString(id[:]), ProfileID: profileID, ProfileName: string(name), Active: true, Mode: c.Mode, IPv6: ipv6, KillSwitchRequested: c.KillSwitch}, nil
}
