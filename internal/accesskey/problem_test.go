package accesskey

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"bimeron/internal/problem"
)

const problemUUID = "123e4567-e89b-12d3-a456-426614174000"

// TestParserProblems checks that parser failures carry a catalog code and the
// canonical field while keeping the historical English message.
func TestParserProblems(t *testing.T) {
	ss2022Key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	cases := []struct {
		name, code, field, message string
		related                    []string
		parse                      func() error
	}{
		{"anytls uri", "uri_invalid", "", "invalid AnyTLS URI", nil, func() error { _, err := ParseAnyTLS("anytls://pw@example.com:443/x"); return err }},
		{"anytls credentials", "uri_credentials_invalid", "Password", "invalid AnyTLS password", nil, func() error { _, err := ParseAnyTLS("anytls://u:pw@example.com:443"); return err }},
		{"anytls insecure", "insecure_tls_unsupported", "Insecure", "unsupported or duplicate AnyTLS option", nil, func() error { _, err := ParseAnyTLS("anytls://pw@example.com:443?insecure=1"); return err }},
		{"anytls server name", "value_required", "ServerName", "invalid AnyTLS server name", nil, func() error { _, err := ParseAnyTLS("anytls://pw@example.com:443?sni="); return err }},
		{"ssh password", "option_not_supported", "Password", "SSH URI passwords are not supported", nil, func() error { _, err := ParseSSH("ssh://alice:pw@example.com"); return err }},
		{"ssh user", "value_required", "Username", "invalid SSH URI", nil, func() error { _, err := ParseSSH("ssh://example.com"); return err }},
		{"ssh identity", "value_required", "IdentityFile", "unsupported or duplicate SSH option", nil, func() error { _, err := ParseSSH("ssh://alice@example.com?identity="); return err }},
		{"hysteria2 port", "port_invalid", "Port", "invalid Hysteria2 port", nil, func() error { _, err := ParseHysteria2("hy2://pw@example.com"); return err }},
		{"hysteria2 option", "uri_option_unsupported", "", "unsupported or duplicate Hysteria2 option", nil, func() error { _, err := ParseHysteria2("hy2://pw@example.com:443?obfs=salamander"); return err }},
		{"hysteria2 alpn", "alpn_invalid", "ALPN", "unsupported Hysteria2 ALPN", nil, func() error { _, err := ParseHysteria2("hy2://pw@example.com:443?alpn=h2"); return err }},
		{"hysteria2 fingerprint", "fingerprint_unsupported", "Fingerprint", "unsupported Hysteria2 QUIC fingerprint", nil, func() error { _, err := ParseHysteria2("hy2://pw@example.com:443?fp=safari"); return err }},
		{"hysteria2 endpoint", "port_invalid", "Port", "invalid Hysteria2 server endpoint", nil, func() error { _, err := ParseHysteria2("hy2://pw@example.com:0"); return err }},
		{"trojan password", "value_required", "Password", "invalid Trojan URI", nil, func() error { _, err := ParseTrojan("trojan://example.com:443"); return err }},
		{"trojan security", "choice_invalid", "Security", "unsupported Trojan transport or security", nil, func() error { _, err := ParseTrojan("trojan://pw@example.com:443?security=reality"); return err }},
		{"trojan ws option", "option_requires_transport", "WSPath", "unsupported Trojan transport options", []string{"Network"}, func() error { _, err := ParseTrojan("trojan://pw@example.com:443?path=%2Fws"); return err }},
		{"trojan ws early data", "path_early_data_unsupported", "WSPath", "invalid or unsupported Trojan WebSocket path", nil, func() error {
			_, err := ParseTrojan("trojan://pw@example.com:443?type=ws&path=%2Fws%3Fed%3D2048")
			return err
		}},
		{"trojan grpc service", "value_required", "GRPCServiceName", "invalid Trojan gRPC service name", nil, func() error { _, err := ParseTrojan("trojan://pw@example.com:443?type=grpc"); return err }},
		{"trojan alpn", "alpn_invalid", "ALPN", "invalid Trojan ALPN", []string{"Network"}, func() error {
			_, err := ParseTrojan("trojan://pw@example.com:443?type=grpc&serviceName=svc&alpn=http%2F1.1")
			return err
		}},
		{"vless id", "uuid_invalid", "ID", "invalid VLESS user ID", nil, func() error {
			_, err := ParseVLESS("vless://bad@example.com:443?encryption=none&type=tcp&security=tls")
			return err
		}},
		{"vless encryption", "choice_invalid", "Encryption", "unsupported VLESS transport, security, encryption or flow", nil, func() error {
			_, err := ParseVLESS("vless://" + problemUUID + "@example.com:443?type=tcp&security=tls")
			return err
		}},
		{"vless network", "choice_invalid", "Network", "unsupported VLESS transport, security or flow", nil, func() error {
			_, err := ParseVLESS("vless://" + problemUUID + "@example.com:443?encryption=none&type=quic&security=tls")
			return err
		}},
		{"vless flow combination", "combination_unsupported", "Flow", "unsupported VLESS transport, security or flow", []string{"Network", "Security"}, func() error {
			_, err := ParseVLESS("vless://" + problemUUID + "@example.com:443?encryption=none&type=tcp&security=tls&flow=xtls-rprx-vision")
			return err
		}},
		{"vless reality public key", "reality_public_key_invalid", "PublicKey", "invalid VLESS REALITY public key", nil, func() error {
			_, err := ParseVLESS("vless://" + problemUUID + "@example.com:443?encryption=none&type=tcp&security=reality&sni=example.com&fp=chrome&pbk=short")
			return err
		}},
		{"vless reality short id", "reality_short_id_invalid", "ShortID", "invalid VLESS REALITY short ID", nil, func() error {
			_, err := ParseVLESS("vless://" + problemUUID + "@example.com:443?encryption=none&type=tcp&security=reality&sni=example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abc")
			return err
		}},
		{"vless reality option", "option_requires_security", "PublicKey", "REALITY options require security=reality", []string{"Security"}, func() error {
			_, err := ParseVLESS("vless://" + problemUUID + "@example.com:443?encryption=none&type=tcp&security=tls&pbk=x")
			return err
		}},
		{"vless transport option", "option_requires_transport", "GRPCServiceName", "VLESS option does not match transport", []string{"Network"}, func() error {
			_, err := ParseVLESS("vless://" + problemUUID + "@example.com:443?encryption=none&type=tcp&security=tls&serviceName=svc")
			return err
		}},
		{"vless grpc service", "grpc_service_name_invalid", "GRPCServiceName", "invalid VLESS gRPC service name", nil, func() error {
			_, err := ParseVLESS("vless://" + problemUUID + "@example.com:443?encryption=none&type=grpc&security=tls&serviceName=a%2Fb")
			return err
		}},
		{"vless early data", "number_out_of_range", "WSEarlyData", "invalid VLESS WebSocket early data", nil, func() error {
			_, err := ParseVLESS("vless://" + problemUUID + "@example.com:443?encryption=none&type=ws&security=tls&ed=0")
			return err
		}},
		{"vless http3 fingerprint", "http3_fingerprint_unsupported", "Fingerprint", "HTTP/3 requires TLS without a TLS fingerprint", []string{"ALPN"}, func() error {
			_, err := ParseVLESS("vless://" + problemUUID + "@example.com:443?encryption=none&type=xhttp&security=tls&mode=packet-up&alpn=h3&fp=chrome")
			return err
		}},
		{"ss cipher", "choice_invalid", "Method", "unsupported Shadowsocks cipher", nil, func() error { _, err := ParseSS("ss://rc4-md5:pw@example.com:8388"); return err }},
		{"ss endpoint", "port_invalid", "Port", "invalid server endpoint", nil, func() error { _, err := ParseSS("ss://aes-256-gcm:pw@example.com:0"); return err }},
		{"ss option", "uri_option_unsupported", "", "unsupported ss option", nil, func() error { _, err := ParseSS("ss://aes-256-gcm:pw@example.com:8388?x=1"); return err }},
		{"ss2022 prefix", "option_not_supported", "Prefix", "Shadowsocks 2022 does not support salt prefixes", []string{"Method"}, func() error {
			_, err := ParseSS("ss://2022-blake3-aes-128-gcm:" + ss2022Key + "@example.com:8388?prefix=x")
			return err
		}},
		{"ss2022 key", "ss2022_key_invalid", "Password", "invalid Shadowsocks 2022 key", nil, func() error {
			return Endpoint{Host: "example.com", Port: 8388, Cipher: "2022-blake3-aes-256-gcm", Secret: ss2022Key}.Validate()
		}},
		{"ss2022 chain", "ss2022_identity_requires_aes", "Password", "Shadowsocks 2022 identity chains require an AES method", []string{"Method"}, func() error {
			_, err := ParseSS2022Keys("2022-blake3-chacha20-poly1305", ss2022Key+":"+ss2022Key)
			return err
		}},
		{"ss empty password", "value_required", "Password", "empty password", nil, func() error { return Endpoint{Host: "example.com", Port: 8388, Cipher: "aes-256-gcm"}.Validate() }},
		{"socks5 credentials", "credentials_incomplete", "Password", "socks5 username and password must both be set", []string{"Username"}, func() error {
			_, err := ParseSOCKS5("socks5://alice@example.com:1080")
			return err
		}},
		{"socks5 length", "value_too_long", "Username", "socks5 credentials are too long", nil, func() error {
			_, err := ParseSOCKS5("socks5://" + strings.Repeat("a", 256) + ":pw@example.com:1080")
			return err
		}},
		{"http endpoint", "port_invalid", "Port", "invalid HTTP proxy endpoint", nil, func() error { _, err := ParseHTTPConnect("http://example.com:70000"); return err }},
		{"http credentials", "value_has_invalid_characters", "Password", "invalid HTTP proxy credentials", nil, func() error {
			_, err := ParseHTTPConnect("http://alice:p%0Aw@example.com:8080")
			return err
		}},
		{"ssconf config", "ssconf_config_invalid", "", "mixed config formats", nil, func() error {
			_, err := ParseConfig([]byte("server: example.com\ntransport:\n  $type: tcpudp\n"))
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.parse()
			p, ok := problem.As(err)
			if !ok {
				t.Fatalf("error %v is not a problem", err)
			}
			if p.Code != tc.code || p.Field != tc.field || p.Message != tc.message || strings.Join(p.Related, ",") != strings.Join(tc.related, ",") {
				t.Fatalf("problem = %+v", p)
			}
			if p.Section != "" || !problem.Known(p.Code) {
				t.Fatalf("problem has a section or unknown code: %+v", p)
			}
			data, _ := json.Marshal(p)
			for _, secret := range []string{"pw", ss2022Key, "alice"} {
				if strings.Contains(string(data), `"`+secret) || strings.Contains(string(data), secret+`"`) {
					t.Fatalf("problem leaked %q: %s", secret, data)
				}
			}
		})
	}
}

// TestVLESSParameterProblems covers explicit parameters, which skip URI parsing.
func TestVLESSParameterProblems(t *testing.T) {
	base := VLESS{ID: problemUUID, Encryption: "none", Network: "ws", Security: "tls"}
	cases := []struct {
		name, code, field string
		edit              func(*VLESS)
		port              int
	}{
		{"server", "host_invalid", "Server", func(*VLESS) {}, 443},
		{"port", "port_invalid", "Port", func(*VLESS) {}, 0},
		{"ws host", "host_invalid", "WSHost", func(v *VLESS) { v.WSHost = "a/b" }, 443},
		{"early data range", "number_out_of_range", "WSEarlyData", func(v *VLESS) { v.WSEarlyData = 9000 }, 443},
		{"xhttp option", "option_requires_transport", "XHTTPPath", func(v *VLESS) { v.XHTTPPath = "/x" }, 443},
		{"reality ws", "combination_unsupported", "Security", func(v *VLESS) { v.Security = "reality" }, 443},
		{"alpn", "alpn_invalid", "ALPN", func(v *VLESS) { v.ALPN = "h2" }, 443},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := base
			tc.edit(&v)
			host := "example.com"
			if tc.name == "server" {
				host = "bad host"
			}
			p, ok := problem.As(v.Validate(host, tc.port))
			if !ok || p.Code != tc.code || p.Field != tc.field {
				t.Fatalf("problem = %+v", p)
			}
		})
	}
	if err := base.Validate("example.com", 443); err != nil {
		t.Fatalf("valid VLESS parameters rejected: %v", err)
	}
}
