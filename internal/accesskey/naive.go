package accesskey

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Naive contains credentials for an HTTPS CONNECT proxy.
type Naive struct{ User, Password, ServerName string }

func (n Naive) Validate(host string, port int) error {
	if host == "" || strings.ContainsAny(host, " /\t\r\n") || port < 1 || port > 65535 {
		return fmt.Errorf("invalid NaiveProxy endpoint")
	}
	if n.User == "" || n.Password == "" || strings.Contains(n.User, ":") || strings.ContainsAny(n.User+n.Password, "\r\n") {
		return fmt.Errorf("invalid NaiveProxy credentials")
	}
	if n.ServerName == "" || strings.ContainsAny(n.ServerName, " /\t\r\n") {
		return fmt.Errorf("invalid NaiveProxy server name")
	}
	return nil
}

// ParseNaive never includes credentials or the input URI in errors.
func ParseNaive(raw string) (Profile, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "naive+https" || u.Opaque != "" || u.Hostname() == "" || u.User == nil || u.Path != "" {
		return Profile{}, fmt.Errorf("invalid NaiveProxy URI")
	}
	password, ok := u.User.Password()
	if !ok {
		return Profile{}, fmt.Errorf("invalid NaiveProxy credentials")
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return Profile{}, fmt.Errorf("invalid NaiveProxy port")
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Profile{}, fmt.Errorf("invalid NaiveProxy options")
	}
	for key, values := range q {
		if (key != "sni" && key != "insecure") || len(values) != 1 || (key == "insecure" && values[0] != "0") {
			return Profile{}, fmt.Errorf("unsupported or duplicate NaiveProxy option")
		}
	}
	n := Naive{User: u.User.Username(), Password: password, ServerName: q.Get("sni")}
	if !q.Has("sni") {
		n.ServerName = u.Hostname()
	}
	if err := n.Validate(u.Hostname(), port); err != nil {
		return Profile{}, err
	}
	return Profile{Type: "naive", Name: u.Fragment, TCP: Endpoint{Host: u.Hostname(), Port: port}, Naive: n}, nil
}
