package accesskey

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// TUIC holds the TUIC v5 credentials and TLS settings.
type TUIC struct {
	ID, Password, ServerName, ALPN string
}

func (t TUIC) Validate(host string, port int) error {
	if host == "" || strings.ContainsAny(host, " /\t\r\n") || port < 1 || port > 65535 {
		return fmt.Errorf("invalid TUIC server endpoint")
	}
	if !uuidPattern.MatchString(t.ID) {
		return fmt.Errorf("invalid TUIC user ID")
	}
	if t.Password == "" || strings.ContainsAny(t.Password, "\r\n") {
		return fmt.Errorf("invalid TUIC password")
	}
	if t.ServerName == "" || strings.ContainsAny(t.ServerName, " /\t\r\n") {
		return fmt.Errorf("invalid TUIC server name")
	}
	if t.ALPN == "" || strings.ContainsAny(t.ALPN, " ,\t\r\n") {
		return fmt.Errorf("invalid TUIC ALPN")
	}
	return nil
}

func (t TUIC) UUID() [16]byte {
	var id [16]byte
	clean := strings.ReplaceAll(t.ID, "-", "")
	_, _ = hex.Decode(id[:], []byte(clean))
	return id
}

// ParseTUIC accepts a strict TUIC v5 URI without exposing credentials in errors.
func ParseTUIC(raw string) (Profile, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "tuic" || u.User == nil || u.Hostname() == "" || u.Path != "" {
		return Profile{}, fmt.Errorf("invalid TUIC URI")
	}
	password, ok := u.User.Password()
	if !ok {
		return Profile{}, fmt.Errorf("invalid TUIC credentials")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return Profile{}, fmt.Errorf("invalid TUIC port")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, fmt.Errorf("invalid TUIC options")
	}
	for key, values := range q {
		if (key != "sni" && key != "alpn" && key != "udp_relay_mode") || len(values) != 1 {
			return Profile{}, fmt.Errorf("unsupported or duplicate TUIC option")
		}
	}
	if q.Has("udp_relay_mode") && q.Get("udp_relay_mode") != "quic" {
		return Profile{}, fmt.Errorf("unsupported TUIC UDP relay mode")
	}
	t := TUIC{ID: u.User.Username(), Password: password, ServerName: q.Get("sni"), ALPN: q.Get("alpn")}
	if !q.Has("sni") {
		t.ServerName = u.Hostname()
	}
	if !q.Has("alpn") {
		t.ALPN = "h3"
	}
	if err := t.Validate(u.Hostname(), port); err != nil {
		return Profile{}, err
	}
	e := Endpoint{Host: u.Hostname(), Port: port}
	return Profile{Type: "tuic", Name: u.Fragment, TCP: e, UDP: e, TUIC: t}, nil
}
