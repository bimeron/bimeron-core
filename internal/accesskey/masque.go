package accesskey

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yosida95/uritemplate/v3"
)

const DefaultMASQUEPath = "/.well-known/masque/udp/{target_host}/{target_port}/"

// MASQUE selects the RFC 9298 HTTP/3 datagram profile. CAFile adds a local CA.
type MASQUE struct {
	ServerName, ProxyHost, UDPPath, CAFile string
}

func (m MASQUE) Validate(host string, port int, user, password string) error {
	if host == "" || strings.ContainsAny(host, " /\t\r\n") || port < 1 || port > 65535 {
		return fmt.Errorf("invalid MASQUE endpoint")
	}
	if m.ServerName == "" || strings.ContainsAny(m.ServerName, " /\t\r\n") {
		return fmt.Errorf("invalid MASQUE server name")
	}
	if (user == "") != (password == "") || strings.ContainsAny(user, ":\r\n") || strings.ContainsAny(password, "\r\n") {
		return fmt.Errorf("invalid MASQUE credentials")
	}
	if m.ProxyHost != "" && strings.ContainsAny(m.ProxyHost, " /\t\r\n?#") {
		return fmt.Errorf("invalid MASQUE proxy authority")
	}
	path := m.UDPPath
	if path == "" {
		path = DefaultMASQUEPath
	}
	// Keep authority and credentials outside the template. Only RFC 6570 simple
	// expansion is supported, so target input cannot change the proxy authority.
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\r\n\t ") || strings.Count(path, "{target_host}") != 1 || strings.Count(path, "{target_port}") != 1 {
		return fmt.Errorf("invalid MASQUE UDP path template")
	}
	rest := strings.ReplaceAll(strings.ReplaceAll(path, "{target_host}", ""), "{target_port}", "")
	if strings.ContainsAny(rest, "{}") {
		return fmt.Errorf("unsupported MASQUE template expansion")
	}
	if _, err := uritemplate.New(path); err != nil {
		return fmt.Errorf("invalid MASQUE UDP path template")
	}
	return nil
}

// ParseMASQUE is an explicit opt-in: https:// alone never enables UDP.
func ParseMASQUE(raw string) (Profile, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "masque" || u.Opaque != "" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
		return Profile{}, fmt.Errorf("invalid MASQUE URI")
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return Profile{}, fmt.Errorf("invalid MASQUE port")
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, fmt.Errorf("invalid MASQUE options")
	}
	for key, values := range q {
		if (key != "sni" && key != "udp_path" && key != "ca") || len(values) != 1 || values[0] == "" {
			return Profile{}, fmt.Errorf("unsupported or duplicate MASQUE option")
		}
	}
	user, password := "", ""
	if u.User != nil {
		user = u.User.Username()
		password, _ = u.User.Password()
		if user == "" || password == "" {
			return Profile{}, fmt.Errorf("invalid MASQUE credentials")
		}
	}
	if q.Get("ca") != "" && !filepath.IsAbs(q.Get("ca")) {
		return Profile{}, fmt.Errorf("MASQUE URI requires an absolute CA path")
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
