package accesskey

import (
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

// ShadowTLS describes an optional strict-v3 wrapper around an encrypted TCP
// upstream. Its credentials and handshake name are independent of the backend.
type ShadowTLS struct{ ServerName, Password string }

func (s ShadowTLS) Validate() error {
	validName := s.ServerName != "" && len(s.ServerName) <= 253
	if net.ParseIP(s.ServerName) == nil {
		for _, label := range strings.Split(strings.TrimSuffix(s.ServerName, "."), ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				validName = false
				break
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
					validName = false
				}
			}
		}
	}
	if !validName {
		return fmt.Errorf("invalid ShadowTLS server name")
	}
	if s.Password == "" || !utf8.ValidString(s.Password) || strings.ContainsAny(s.Password, "\x00\r\n") {
		return fmt.Errorf("invalid ShadowTLS password")
	}
	return nil
}

// ValidateShadowTLS is shared by parsed profiles and direct Go API callers.
func (p Profile) ValidateShadowTLS() error {
	if p.ShadowTLS == nil {
		return nil
	}
	if p.SSPlugin != nil {
		return fmt.Errorf("ShadowTLS cannot be combined with a Shadowsocks plugin")
	}
	if err := p.ShadowTLS.Validate(); err != nil {
		return err
	}
	switch p.Type {
	case "", "ss", "shadowsocks":
		if err := p.TCP.Validate(); err != nil {
			return err
		}
		if p.TCP.Cipher == "aes-192-gcm" {
			return fmt.Errorf("ShadowTLS does not support this Shadowsocks cipher")
		}
	case "vless":
		if err := p.VLESS.Validate(p.TCP.Host, p.TCP.Port); err != nil {
			return err
		}
		if p.VLESS.Security != "tls" && p.VLESS.Security != "reality" {
			return fmt.Errorf("ShadowTLS requires encrypted VLESS transport")
		}
		if err := shadowXHTTP(p.VLESS.ALPN, p.VLESS.XHTTPOptions); err != nil {
			return err
		}
	case "vmess":
		if err := p.VMess.Validate(p.TCP.Host, p.TCP.Port); err != nil {
			return err
		}
		if err := shadowXHTTP(p.VMess.ALPN, p.VMess.XHTTPOptions); err != nil {
			return err
		}
	case "trojan":
		return p.Trojan.Validate(p.TCP.Host, p.TCP.Port)
	case "anytls":
		return p.AnyTLS.Validate(p.TCP.Host, p.TCP.Port)
	case "naive":
		if p.Naive.QUIC {
			return fmt.Errorf("ShadowTLS does not support HTTP/3")
		}
		return p.Naive.Validate(p.TCP.Host, p.TCP.Port)
	case "ssh":
		if p.SSH.User == "" || p.TCP.Host == "" || p.TCP.Port < 1 || p.TCP.Port > 65535 {
			return fmt.Errorf("invalid SSH profile")
		}
	default:
		return fmt.Errorf("ShadowTLS requires a supported encrypted TCP upstream")
	}
	return nil
}

func shadowXHTTP(alpn string, options *XHTTPOptions) error {
	if strings.Contains(alpn, "h3") || options != nil && options.DownloadSettings != nil && strings.Contains(options.DownloadSettings.ALPN, "h3") {
		return fmt.Errorf("ShadowTLS does not support HTTP/3")
	}
	return nil
}

// TCPOnly identifies the profiles whose packet backend must use DNS-over-TCP
// and drop other proxy-routed UDP rather than constructing a native fallback.
func (p Profile) TCPOnly() bool {
	return p.SSPlugin != nil || p.Type == "ssh" || p.Type == "http" || p.Type == "naive" ||
		(p.ShadowTLS != nil && (p.Type == "" || p.Type == "ss" || p.Type == "shadowsocks"))
}
