package accesskey

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// SSPlugin describes the embedded v2ray-plugin transport, never an executable.
type SSPlugin struct {
	TLS        bool
	Host, Path string
	Mux        uint32
}

// ParseSSPlugin parses SIP003 options after the URI query has been decoded.
func ParseSSPlugin(name, options string) (*SSPlugin, error) {
	if len(name)+len(options) > maxBytes {
		return nil, fmt.Errorf("plugin options too large")
	}
	if name == "" && options == "" {
		return nil, nil
	}
	if name != "v2ray-plugin" {
		return nil, fmt.Errorf("unsupported Shadowsocks plugin")
	}
	p := &SSPlugin{Host: "cloudfront.com", Path: "/", Mux: 1}
	seen := map[string]bool{}
	for options != "" {
		var key, value strings.Builder
		hasValue := false
		i := 0
		for ; i < len(options); i++ {
			b := options[i]
			if b == ';' {
				i++
				break
			}
			if b == '=' && !hasValue {
				hasValue = true
				continue
			}
			if b == '\\' {
				i++
				if i == len(options) {
					return nil, fmt.Errorf("invalid plugin escape")
				}
				b = options[i]
			}
			if hasValue {
				value.WriteByte(b)
			} else {
				key.WriteByte(b)
			}
		}
		options = options[i:]
		k, v := key.String(), value.String()
		if k == "" || seen[k] {
			return nil, fmt.Errorf("invalid or duplicate plugin option")
		}
		seen[k] = true
		switch k {
		case "tls":
			p.TLS = true // SIP003 upstream enables TLS by presence, including tls=false.
		case "mode":
			if !hasValue || v != "websocket" {
				return nil, fmt.Errorf("unsupported plugin mode")
			}
		case "host":
			if !hasValue {
				return nil, fmt.Errorf("invalid plugin host")
			}
			p.Host = v
		case "path":
			if !hasValue {
				return nil, fmt.Errorf("invalid plugin path")
			}
			p.Path = v
		case "mux":
			if !hasValue || v == "" || strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return nil, fmt.Errorf("invalid plugin mux concurrency")
			}
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin mux concurrency")
			}
			p.Mux = uint32(n)
		default:
			return nil, fmt.Errorf("unsupported plugin option")
		}
	}
	if p.Path == "" {
		p.Path = "/"
	} else if p.Path[0] != '/' {
		p.Path = "/" + p.Path
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p SSPlugin) Validate() error {
	if p.Host == "" || len(p.Host) > 253 || !httpguts.ValidHostHeader(p.Host) || strings.ContainsAny(p.Host, " /\\\t\r\n?#@") {
		return fmt.Errorf("invalid plugin host")
	}
	// Host is also the certificate name, so an authority containing a port is unsupported.
	if strings.Contains(p.Host, ":") && net.ParseIP(p.Host) == nil {
		return fmt.Errorf("invalid plugin host")
	}
	u, err := url.ParseRequestURI(p.Path)
	if err != nil || !strings.HasPrefix(p.Path, "/") || strings.HasPrefix(p.Path, "//") || u.IsAbs() || u.Host != "" || u.Fragment != "" || strings.ContainsAny(p.Path, "\r\n\\#") {
		return fmt.Errorf("invalid plugin path")
	}
	return nil
}

func parseSSPluginQuery(value string) (*SSPlugin, error) {
	name, options, _ := strings.Cut(value, ";")
	if name == "" {
		return nil, fmt.Errorf("invalid Shadowsocks plugin")
	}
	return ParseSSPlugin(name, options)
}
