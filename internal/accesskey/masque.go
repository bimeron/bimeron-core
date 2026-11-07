package accesskey

import (
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yosida95/uritemplate/v3"

	"bimeron/internal/problem"
)

const DefaultMASQUEPath = "/.well-known/masque/udp/{target_host}/{target_port}/"

// MASQUE selects the RFC 9298 HTTP/3 datagram profile. CAFile adds a local CA.
type MASQUE struct {
	ServerName, ProxyHost, UDPPath, CAFile string
}

func (m MASQUE) Validate(host string, port int, user, password string) error {
	if host == "" || strings.ContainsAny(host, " /\t\r\n") {
		return problem.New("host_invalid", "invalid MASQUE endpoint").At("Server")
	}
	if port < 1 || port > 65535 {
		return problem.New("port_invalid", "invalid MASQUE endpoint").At("Port")
	}
	if m.ServerName == "" || strings.ContainsAny(m.ServerName, " /\t\r\n") {
		return problem.New("server_name_invalid", "invalid MASQUE server name").At("ServerName")
	}
	const credentials = "invalid MASQUE credentials"
	if user == "" && password != "" {
		return problem.New("credentials_incomplete", credentials).On("Username", "").Also("Password")
	}
	if user != "" && password == "" {
		return problem.New("credentials_incomplete", credentials).On("Password", "").Also("Username")
	}
	if strings.ContainsAny(user, ":\r\n") {
		return problem.New("value_has_invalid_characters", credentials).At("Username")
	}
	if strings.ContainsAny(password, "\r\n") {
		return problem.New("value_has_invalid_characters", credentials).On("Password", password)
	}
	if m.ProxyHost != "" && strings.ContainsAny(m.ProxyHost, " /\t\r\n?#") {
		return problem.New("host_invalid", "invalid MASQUE proxy authority").At("Server")
	}
	path := m.UDPPath
	if path == "" {
		path = DefaultMASQUEPath
	}
	// Keep authority and credentials outside the template. Only RFC 6570 simple
	// expansion is supported, so target input cannot change the proxy authority.
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\r\n\t ") || strings.Count(path, "{target_host}") != 1 || strings.Count(path, "{target_port}") != 1 {
		return masquePathProblem("invalid MASQUE UDP path template")
	}
	rest := strings.ReplaceAll(strings.ReplaceAll(path, "{target_host}", ""), "{target_port}", "")
	if strings.ContainsAny(rest, "{}") {
		return masquePathProblem("unsupported MASQUE template expansion")
	}
	if _, err := uritemplate.New(path); err != nil {
		return masquePathProblem("invalid MASQUE UDP path template")
	}
	return nil
}

func masquePathProblem(message string) *problem.Error {
	return problem.New("masque_path_invalid", message).At("MASQUEPath").Arg("host_variable", "{target_host}").Arg("port_variable", "{target_port}")
}

// ParseMASQUE is an explicit opt-in: https:// alone never enables UDP.
func ParseMASQUE(raw string) (Profile, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "masque" || u.Opaque != "" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
		return Profile{}, problem.New("uri_invalid", "invalid MASQUE URI")
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return Profile{}, problem.New("port_invalid", "invalid MASQUE port").At("Port")
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, problem.New("uri_invalid", "invalid MASQUE options")
	}
	for key, values := range q {
		if (key != "sni" && key != "udp_path" && key != "ca") || len(values) != 1 || values[0] == "" {
			return Profile{}, problem.New("uri_option_unsupported", "unsupported or duplicate MASQUE option")
		}
	}
	user, password := "", ""
	if u.User != nil {
		user = u.User.Username()
		password, _ = u.User.Password()
		if user == "" {
			return Profile{}, problem.New("credentials_incomplete", "invalid MASQUE credentials").On("Username", "").Also("Password")
		}
		if password == "" {
			return Profile{}, problem.New("credentials_incomplete", "invalid MASQUE credentials").On("Password", "").Also("Username")
		}
	}
	if q.Get("ca") != "" && !filepath.IsAbs(q.Get("ca")) {
		return Profile{}, problem.New("path_must_be_absolute", "MASQUE URI requires an absolute CA path").At("CAFile")
	}
	m := MASQUE{ProxyHost: u.Hostname(), ServerName: q.Get("sni"), UDPPath: q.Get("udp_path"), CAFile: q.Get("ca")}
	if m.ServerName == "" {
		m.ServerName = u.Hostname()
	}
	if m.UDPPath == "" {
		m.UDPPath = DefaultMASQUEPath
	}
	if err := m.Validate(u.Hostname(), port, user, password); err != nil {
		return Profile{}, err
	}
	e := Endpoint{Host: u.Hostname(), Port: port, Secret: password}
	return Profile{Type: "masque", Name: u.Fragment, Username: user, TCP: e, UDP: e, MASQUE: m}, nil
}
