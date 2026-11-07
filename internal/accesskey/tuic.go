package accesskey

import (
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"

	"bimeron/internal/problem"
)

// TUIC holds the TUIC v5 credentials and TLS settings.
type TUIC struct {
	ID, Password, ServerName, ALPN string
}

func (t TUIC) Validate(host string, port int) error {
	if host == "" || strings.ContainsAny(host, " /\t\r\n") {
		return problem.New("host_invalid", "invalid TUIC server endpoint").At("Server")
	}
	if port < 1 || port > 65535 {
		return problem.New("port_invalid", "invalid TUIC server endpoint").At("Port")
	}
	if !uuidPattern.MatchString(t.ID) {
		return problem.New("uuid_invalid", "invalid TUIC user ID").On("ID", t.ID)
	}
	if t.Password == "" {
		return problem.New("value_required", "invalid TUIC password").On("Password", "")
	}
	if strings.ContainsAny(t.Password, "\r\n") {
		return problem.New("value_has_invalid_characters", "invalid TUIC password").On("Password", t.Password)
	}
	if t.ServerName == "" || strings.ContainsAny(t.ServerName, " /\t\r\n") {
		return problem.New("server_name_invalid", "invalid TUIC server name").At("ServerName")
	}
	if t.ALPN == "" {
		return problem.New("value_required", "invalid TUIC ALPN").On("ALPN", "")
	}
	if strings.ContainsAny(t.ALPN, " ,\t\r\n") {
		return problem.New("value_has_invalid_characters", "invalid TUIC ALPN").At("ALPN")
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
		return Profile{}, problem.New("uri_invalid", "invalid TUIC URI")
	}
	password, ok := u.User.Password()
	if !ok {
		return Profile{}, problem.New("value_required", "invalid TUIC credentials").On("Password", "")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return Profile{}, problem.New("port_invalid", "invalid TUIC port").At("Port")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, problem.New("uri_invalid", "invalid TUIC options")
	}
	for key, values := range q {
		if (key != "sni" && key != "alpn" && key != "udp_relay_mode") || len(values) != 1 {
			return Profile{}, problem.New("uri_option_unsupported", "unsupported or duplicate TUIC option")
		}
	}
	if q.Has("udp_relay_mode") && q.Get("udp_relay_mode") != "quic" {
		return Profile{}, problem.New("choice_invalid", "unsupported TUIC UDP relay mode").At("UDPRelayMode").Arg("allowed", "quic")
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
