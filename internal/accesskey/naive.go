package accesskey

import (
	"net/url"
	"strconv"
	"strings"

	"bimeron/internal/problem"
)

// Naive contains credentials and transport selection for an HTTPS CONNECT proxy.
type Naive struct {
	User, Password, ServerName string
	QUIC                       bool // HTTP/3; false retains the HTTP/2 default.
}

func (n Naive) Validate(host string, port int) error {
	if host == "" || strings.ContainsAny(host, " /\t\r\n") {
		return problem.New("host_invalid", "invalid NaiveProxy endpoint").At("Server")
	}
	if port < 1 || port > 65535 {
		return problem.New("port_invalid", "invalid NaiveProxy endpoint").At("Port")
	}
	const credentials = "invalid NaiveProxy credentials"
	if n.User == "" {
		return problem.New("value_required", credentials).On("Username", "")
	}
	if n.Password == "" {
		return problem.New("value_required", credentials).On("Password", "")
	}
	if strings.ContainsAny(n.User, ":\r\n") {
		return problem.New("value_has_invalid_characters", credentials).At("Username")
	}
	if strings.ContainsAny(n.Password, "\r\n") {
		return problem.New("value_has_invalid_characters", credentials).On("Password", n.Password)
	}
	if n.ServerName == "" || strings.ContainsAny(n.ServerName, " /\t\r\n") {
		return problem.New("server_name_invalid", "invalid NaiveProxy server name").At("ServerName")
	}
	return nil
}

// ParseNaive never includes credentials or the input URI in errors.
func ParseNaive(raw string) (Profile, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "naive+https" && u.Scheme != "naive+quic") || u.Opaque != "" || u.Hostname() == "" || u.User == nil || u.Path != "" {
		return Profile{}, problem.New("uri_invalid", "invalid NaiveProxy URI")
	}
	password, ok := u.User.Password()
	if !ok {
		return Profile{}, problem.New("value_required", "invalid NaiveProxy credentials").On("Password", "")
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return Profile{}, problem.New("port_invalid", "invalid NaiveProxy port").At("Port")
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, problem.New("uri_invalid", "invalid NaiveProxy options")
	}
	for key, values := range q {
		if (key != "sni" && key != "insecure") || len(values) != 1 || (key == "insecure" && values[0] != "0") {
			return Profile{}, problem.New("uri_option_unsupported", "unsupported or duplicate NaiveProxy option")
		}
	}
	n := Naive{User: u.User.Username(), Password: password, ServerName: q.Get("sni"), QUIC: u.Scheme == "naive+quic"}
	if !q.Has("sni") {
		n.ServerName = u.Hostname()
	}
	if err := n.Validate(u.Hostname(), port); err != nil {
		return Profile{}, err
	}
	return Profile{Type: "naive", Name: u.Fragment, TCP: Endpoint{Host: u.Hostname(), Port: port}, Naive: n}, nil
}
