package config

import (
	"slices"

	"bimeron/internal/accesskey"
	"bimeron/internal/problem"
)

// ExplicitAccess lists the protocols that [AccessKey] accepts as explicit
// parameters. "naive_quic" is Type = naive with Network = quic.
var ExplicitAccess = []string{"shadowsocks", "socks5", "http", "https", "vless", "ssh", "trojan", "naive", "masque", "hysteria2", "tuic", "anytls", "vmess", "naive_quic"}

// explicitTypes builds the profiles whose explicit form mirrors a URI-only
// protocol. Each builder applies the same defaults and validation as the URI.
var explicitTypes = map[string]func(*File, *Parameters) (*accesskey.Profile, error){
	"hysteria2": explicitHysteria2,
	"tuic":      explicitTUIC,
	"anytls":    explicitAnyTLS,
	"vmess":     explicitVMess,
}

// rejectOthers reports the first set option outside allowed; Server and Port
// are always allowed.
func (c *File) rejectOthers(typ, message string, allowed ...string) error {
	var others []string
	for _, field := range append([]string{"Username", "Method", "Password", "Prefix", "ServerName"}, vlessFields...) {
		if !slices.Contains(allowed, field) {
			others = append(others, field)
		}
	}
	if c.present(others...) != "" {
		return c.unsupported(typ, message, others...)
	}
	return nil
}

func (c *File) explicitServerName(s *Parameters) string {
	if c.Access.ServerName != "" {
		return c.Access.ServerName
	}
	return s.Server
}

func (c *File) vless() accesskey.VLESS {
	if c.Access.VLESSParameters == nil {
		return accesskey.VLESS{}
	}
	return *c.Access.VLESSParameters
}

func explicitHysteria2(c *File, s *Parameters) (*accesskey.Profile, error) {
	const message = "[AccessKey] invalid Hysteria2 parameters"
	if err := c.rejectOthers("Hysteria2", message, "Password", "ServerName", "ALPN", "Fingerprint"); err != nil {
		return nil, err
	}
	v := c.vless()
	h := accesskey.Hysteria2{Password: s.Password, ServerName: c.explicitServerName(s), ALPN: v.ALPN, Fingerprint: v.Fingerprint}
	if err := h.Validate(s.Server, s.Port); err != nil {
		return nil, accessProblem(err)
	}
	e := accesskey.Endpoint{Host: s.Server, Port: s.Port}
	return &accesskey.Profile{Name: c.Name, Type: "hysteria2", TCP: e, UDP: e, Hysteria2: h}, nil
}

func explicitTUIC(c *File, s *Parameters) (*accesskey.Profile, error) {
	const message = "[AccessKey] invalid TUIC parameters"
	if err := c.rejectOthers("TUIC", message, "ID", "Password", "ServerName", "ALPN"); err != nil {
		return nil, err
	}
	v := c.vless()
	t := accesskey.TUIC{ID: v.ID, Password: s.Password, ServerName: c.explicitServerName(s), ALPN: v.ALPN}
	if t.ALPN == "" {
		t.ALPN = "h3"
	}
	if err := t.Validate(s.Server, s.Port); err != nil {
		return nil, accessProblem(err)
	}
	e := accesskey.Endpoint{Host: s.Server, Port: s.Port}
	return &accesskey.Profile{Name: c.Name, Type: "tuic", TCP: e, UDP: e, TUIC: t}, nil
}

func explicitAnyTLS(c *File, s *Parameters) (*accesskey.Profile, error) {
	const message = "[AccessKey] invalid AnyTLS parameters"
	if err := c.rejectOthers("AnyTLS", message, "Password", "ServerName"); err != nil {
		return nil, err
	}
	a := accesskey.AnyTLS{Password: s.Password, ServerName: c.explicitServerName(s)}
	if err := a.Validate(s.Server, s.Port); err != nil {
		return nil, accessProblem(err)
	}
	e := accesskey.Endpoint{Host: s.Server, Port: s.Port}
	return &accesskey.Profile{Name: c.Name, Type: "anytls", TCP: e, UDP: e, AnyTLS: a}, nil
}

func explicitVMess(c *File, s *Parameters) (*accesskey.Profile, error) {
	const message = "[AccessKey] invalid VMess parameters"
	if err := c.rejectOthers("VMess", message, "ID", "Encryption", "Network", "Security", "ServerName", "ALPN", "Fingerprint", "PublicKey", "ShortID", "SpiderX", "WSPath", "WSHost", "GRPCServiceName", "GRPCAuthority", "GRPCMultiMode", "XHTTPPath", "XHTTPHost", "XHTTPMode", "XHTTPExtra", "XHTTP*"); err != nil {
		return nil, err
	}
	p := c.vless()
	v := accesskey.VMess{ID: p.ID, Security: p.Encryption, Network: p.Network, TLS: p.Security, ServerName: c.explicitServerName(s),
		ALPN: p.ALPN, Fingerprint: p.Fingerprint, PublicKey: p.PublicKey, ShortID: p.ShortID, SpiderX: p.SpiderX,
		WSPath: p.WSPath, WSHost: p.WSHost, GRPCServiceName: p.GRPCServiceName, GRPCAuthority: p.GRPCAuthority, GRPCMultiMode: p.GRPCMultiMode,
		XHTTPPath: p.XHTTPPath, XHTTPHost: p.XHTTPHost, XHTTPMode: p.XHTTPMode, XHTTPOptions: p.XHTTPOptions}
	// Defaults match ParseVMess so both forms produce the same profile.
	if v.Security == "" {
		v.Security = "auto"
	}
	if v.Network == "" {
		v.Network = "tcp"
	}
	if (v.Network == "ws" || v.Network == "httpupgrade") && v.WSPath == "" {
		v.WSPath = "/"
	}
	if v.Network == "xhttp" {
		if v.XHTTPPath == "" {
			v.XHTTPPath = "/"
		}
		if v.XHTTPMode == "" {
			v.XHTTPMode = "auto"
		}
	}
	if v.TLS == "" {
		return nil, problem.New("value_required", message).In("AccessKey").On("Security", "")
	}
	if err := v.Validate(s.Server, s.Port); err != nil {
		return nil, c.explicitVMessProblem(err, v.Network)
	}
	e := accesskey.Endpoint{Host: s.Server, Port: s.Port}
	return &accesskey.Profile{Name: c.Name, Type: "vmess", TCP: e, UDP: e, VMess: v}, nil
}

// explicitVMessProblem renames VMess link fields to the explicit options.
func (c *File) explicitVMessProblem(err error, network string) error {
	p, ok := problem.As(err)
	if !ok {
		return err
	}
	rename := func(field string) string {
		switch field {
		case "VMessSecurity":
			return "Encryption"
		case "VMessTLS":
			return "Security"
		case "VMessNetwork":
			return "Network"
		case "VMessPath":
			switch network {
			case "grpc":
				return c.firstOr("GRPCServiceName", "GRPCServiceName", "WSPath", "XHTTPPath")
			case "xhttp":
				return c.firstOr("XHTTPPath", "XHTTPPath", "WSPath", "GRPCServiceName")
			}
			return c.firstOr("WSPath", "WSPath", "GRPCServiceName", "XHTTPPath")
		case "VMessHost":
			switch network {
			case "grpc":
				return c.firstOr("GRPCAuthority", "GRPCAuthority", "WSHost", "XHTTPHost")
			case "xhttp":
				return c.firstOr("XHTTPHost", "XHTTPHost", "WSHost", "GRPCAuthority")
			}
			return c.firstOr("WSHost", "WSHost", "GRPCAuthority", "XHTTPHost")
		case "VMessMode":
			return c.firstOr("XHTTPMode", "XHTTPMode", "GRPCMultiMode")
		case "VMessExtra":
			return c.firstOr("XHTTPExtra", "XHTTPExtra", "XHTTP*")
		}
		return field
	}
	p.Field = rename(p.Field)
	for i, field := range p.Related {
		p.Related[i] = rename(field)
	}
	return accessProblem(p)
}

// firstOr returns the first set option, or fallback when none is set.
func (c *File) firstOr(fallback string, fields ...string) string {
	if field := c.present(fields...); field != "" {
		return field
	}
	return fallback
}

// explicitNaiveQUIC reports whether Naive options select HTTP/3 and rejects
// any other transport option.
func (c *File) explicitNaiveQUIC(message string) (bool, error) {
	var others []string
	for _, field := range vlessFields {
		if field != "Network" {
			others = append(others, field)
		}
	}
	if c.present(others...) != "" {
		return false, c.unsupported("NaiveProxy", message, others...)
	}
	if c.present("Network") == "" {
		return false, nil
	}
	if c.Access.VLESSParameters.Network != "quic" {
		return false, problem.New("choice_invalid", message).In("AccessKey").At("Network").Arg("allowed", "quic")
	}
	return true, nil
}
