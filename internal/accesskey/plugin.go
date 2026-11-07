package accesskey

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"

	"bimeron/internal/problem"
)

// SSPlugin describes an embedded Shadowsocks plugin, never an executable.
type SSPlugin struct {
	Name       string // Empty retains the v2ray-plugin meaning for existing callers.
	Mode       string // obfs-local: http or tls.
	Method     string // obfs-local HTTP request method.
	TLS        bool
	Host, Path string
	Mux        uint32
}

const (
	pluginNames       = "v2ray-plugin, obfs-local"
	v2rayPluginOpts   = "tls, mode, host, path, mux"
	simpleObfsOptions = "obfs, obfs-host, obfs-uri, http-method"
)

// pluginOptionProblem reports an invalid plugin option value. option must be
// one of the constant option names.
func pluginOptionProblem(message, option string) *problem.Error {
	return problem.New("plugin_option_invalid", message).At("PluginOpts").Arg("option", option)
}

// ParseSSPlugin parses SIP003 options after the URI query has been decoded.
func ParseSSPlugin(name, options string) (*SSPlugin, error) {
	if len(name)+len(options) > maxBytes {
		return nil, problem.New("value_too_long", "plugin options too large").On("PluginOpts", options).ArgInt("max", maxBytes)
	}
	if name == "" && options == "" {
		return nil, nil
	}
	if name == "" {
		return nil, problem.New("value_required", "unsupported Shadowsocks plugin").On("Plugin", "")
	}
	if name != "v2ray-plugin" && name != "obfs-local" {
		return nil, problem.New("choice_invalid", "unsupported Shadowsocks plugin").At("Plugin").Arg("allowed", pluginNames)
	}
	all := options
	p := &SSPlugin{Host: "cloudfront.com", Path: "/", Mux: 1}
	if name == "obfs-local" {
		p = &SSPlugin{Name: name, Host: "cloudfront.net"}
	}
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
					return nil, problem.New("plugin_options_invalid", "invalid plugin escape").On("PluginOpts", all)
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
			return nil, problem.New("plugin_options_invalid", "invalid or duplicate plugin option").On("PluginOpts", all)
		}
		seen[k] = true
		if name == "obfs-local" {
			if !hasValue || v == "" {
				return nil, problem.New("plugin_options_invalid", "missing simple-obfs option value").On("PluginOpts", all)
			}
			switch k {
			case "obfs":
				p.Mode = v
			case "obfs-host":
				p.Host = v
			case "obfs-uri":
				p.Path = v
			case "http-method":
				p.Method = v
			default:
				return nil, problem.New("plugin_option_unsupported", "unsupported simple-obfs option").On("PluginOpts", all).Arg("allowed", simpleObfsOptions)
			}
			continue
		}
		switch k {
		case "tls":
			p.TLS = true // SIP003 upstream enables TLS by presence, including tls=false.
		case "mode":
			if !hasValue || v != "websocket" {
				return nil, pluginOptionProblem("unsupported plugin mode", "mode").On("PluginOpts", all)
			}
		case "host":
			if !hasValue {
				return nil, pluginOptionProblem("invalid plugin host", "host").On("PluginOpts", all)
			}
			p.Host = v
		case "path":
			if !hasValue {
				return nil, pluginOptionProblem("invalid plugin path", "path").On("PluginOpts", all)
			}
			p.Path = v
		case "mux":
			if !hasValue || v == "" || strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return nil, pluginOptionProblem("invalid plugin mux concurrency", "mux").On("PluginOpts", all)
			}
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return nil, pluginOptionProblem("invalid plugin mux concurrency", "mux").On("PluginOpts", all)
			}
			p.Mux = uint32(n)
		default:
			return nil, problem.New("plugin_option_unsupported", "unsupported plugin option").On("PluginOpts", all).Arg("allowed", v2rayPluginOpts)
		}
	}
	if name == "obfs-local" {
		if p.Mode == "http" {
			if p.Path == "" {
				p.Path = "/"
			}
			if p.Method == "" {
				p.Method = "GET"
			}
		}
	} else if p.Path == "" {
		p.Path = "/"
	} else if p.Path[0] != '/' {
		p.Path = "/" + p.Path
	}
	if err := p.Validate(); err != nil {
		if pr, ok := problem.As(err); ok && pr.Field == "PluginOpts" {
			pr.On("PluginOpts", all)
		}
		return nil, err
	}
	return p, nil
}

// Validate reports option failures on PluginOpts with the SIP003 option name.
func (p SSPlugin) Validate() error {
	if p.Name != "" && p.Name != "v2ray-plugin" && p.Name != "obfs-local" {
		return problem.New("choice_invalid", "unsupported Shadowsocks plugin").At("Plugin").Arg("allowed", pluginNames)
	}
	hostOption, pathOption := "host", "path"
	if p.Name == "obfs-local" {
		hostOption, pathOption = "obfs-host", "obfs-uri"
		if p.Mode != "http" && p.Mode != "tls" {
			return pluginOptionProblem("invalid simple-obfs settings", "obfs")
		}
		if p.TLS || p.Mux != 0 {
			return problem.New("plugin_option_unsupported", "invalid simple-obfs settings").At("PluginOpts").Arg("allowed", simpleObfsOptions)
		}
		if p.Mode == "tls" && (p.Path != "" || p.Method != "") {
			return problem.New("option_requires_mode", "HTTP options require simple-obfs HTTP mode").At("PluginOpts").Arg("mode", "obfs=http")
		}
		if p.Mode == "http" && (p.Method == "" || len(p.Method) > 64 || !httpguts.ValidHeaderFieldName(p.Method)) {
			return pluginOptionProblem("invalid simple-obfs HTTP method", "http-method")
		}
	} else if p.Mode != "" || p.Method != "" {
		return problem.New("plugin_option_unsupported", "simple-obfs options require obfs-local").At("PluginOpts").Arg("allowed", v2rayPluginOpts)
	}
	if p.Host == "" || len(p.Host) > 253 || !httpguts.ValidHostHeader(p.Host) || strings.ContainsAny(p.Host, " /\\\t\r\n?#@") {
		return pluginOptionProblem("invalid plugin host", hostOption)
	}
	// Host is also the certificate name, so an authority containing a port is unsupported.
	if strings.Contains(p.Host, ":") && net.ParseIP(p.Host) == nil {
		return pluginOptionProblem("invalid plugin host", hostOption)
	}
	if p.Name == "obfs-local" && p.Mode == "tls" {
		return nil
	}
	if p.Name == "obfs-local" && (len(p.Path) > 4096 || strings.IndexFunc(p.Path, func(r rune) bool { return r <= ' ' || r >= 127 }) >= 0) {
		return pluginOptionProblem("invalid simple-obfs HTTP URI", pathOption)
	}
	u, err := url.ParseRequestURI(p.Path)
	if err != nil || !strings.HasPrefix(p.Path, "/") || strings.HasPrefix(p.Path, "//") || u.IsAbs() || u.Host != "" || u.Fragment != "" || strings.ContainsAny(p.Path, "\r\n\\#") {
		return pluginOptionProblem("invalid plugin path", pathOption)
	}
	return nil
}

func parseSSPluginQuery(value string) (*SSPlugin, error) {
	name, options, _ := strings.Cut(value, ";")
	if name == "" {
		return nil, problem.New("value_required", "invalid Shadowsocks plugin").On("Plugin", "")
	}
	return ParseSSPlugin(name, options)
}
