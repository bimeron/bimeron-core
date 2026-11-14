package config

import (
	"encoding/base64"
	"reflect"
	"testing"

	"bimeron/internal/accesskey"
	"bimeron/internal/problem"
)

const testUUID = "123e4567-e89b-12d3-a456-426614174000"
const realityKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func vmessLink(json string) string {
	return "VMess = vmess://" + base64.StdEncoding.EncodeToString([]byte(json))
}

func resolveAccess(t *testing.T, access string) accesskey.Profile {
	t.Helper()
	c, err := ParseData([]byte("[Profile]\nVersion = 1\n[AccessKey]\n" + access + "\n"))
	if err != nil {
		t.Fatalf("parse %q: %v", access, err)
	}
	p, err := c.Resolve(t.Context())
	if err != nil {
		t.Fatalf("resolve %q: %v", access, err)
	}
	p.Name = ""
	return p
}

// TestExplicitAccessMatchesURI requires each explicit form to produce the
// same runtime profile as the equivalent share URI.
func TestExplicitAccessMatchesURI(t *testing.T) {
	cases := []struct{ name, uri, explicit string }{
		{"hysteria2", "Hysteria2 = hysteria2://p%40ss@example.com:443",
			"Type = hysteria2\nServer = example.com\nPort = 443\nPassword = p@ss"},
		{"hysteria2-options", "Hysteria2 = hy2://example.com:8443?auth=secret&sni=front.example&alpn=h3&fp=chrome-146",
			"Type = hysteria2\nServer = example.com\nPort = 8443\nPassword = secret\nServerName = front.example\nALPN = h3\nFingerprint = chrome-146"},
		{"tuic", "TUIC = tuic://" + testUUID + ":secret@example.com:443",
			"Type = tuic\nServer = example.com\nPort = 443\nID = " + testUUID + "\nPassword = secret"},
		{"tuic-options", "TUIC = tuic://" + testUUID + ":secret@example.com:443?sni=front.example&alpn=h3&udp_relay_mode=quic",
			"Type = tuic\nServer = example.com\nPort = 443\nID = " + testUUID + "\nPassword = secret\nServerName = front.example\nALPN = h3"},
		{"anytls", "AnyTLS = anytls://secret@example.com:443",
			"Type = anytls\nServer = example.com\nPort = 443\nPassword = secret"},
		{"anytls-sni", "AnyTLS = anytls://secret@example.com:8443?sni=front.example",
			"Type = anytls\nServer = example.com\nPort = 8443\nPassword = secret\nServerName = front.example"},
		{"naive-quic", "Naive = naive+quic://alice:secret@example.com:443",
			"Type = naive\nServer = example.com\nPort = 443\nUsername = alice\nPassword = secret\nNetwork = quic"},
		{"naive-quic-sni", "Naive = naive+quic://alice:secret@example.com:8443?sni=front.example",
			"Type = naive\nServer = example.com\nPort = 8443\nUsername = alice\nPassword = secret\nServerName = front.example\nNetwork = quic"},
		{"vmess-tcp", vmessLink(`{"v":"2","add":"example.com","port":"443","id":"` + testUUID + `","tls":"tls"}`),
			"Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nSecurity = tls"},
		{"vmess-ws", vmessLink(`{"v":"2","add":"example.com","port":"443","id":"` + testUUID + `","scy":"chacha20-poly1305","net":"ws","path":"/ws","host":"cdn.example.com","tls":"tls","sni":"front.example","alpn":"http/1.1","fp":"firefox"}`),
			"Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nEncryption = chacha20-poly1305\nNetwork = ws\nSecurity = tls\nServerName = front.example\nALPN = http/1.1\nFingerprint = firefox\nWSPath = /ws\nWSHost = cdn.example.com"},
		{"vmess-ws-default-path", vmessLink(`{"v":"2","add":"example.com","port":"443","id":"` + testUUID + `","net":"httpupgrade","tls":"tls"}`),
			"Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nNetwork = httpupgrade\nSecurity = tls"},
		{"vmess-grpc", vmessLink(`{"v":"2","add":"example.com","port":"443","id":"` + testUUID + `","net":"grpc","path":"svc","host":"auth.example","mode":"multi","tls":"tls"}`),
			"Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nNetwork = grpc\nSecurity = tls\nGRPCServiceName = svc\nGRPCAuthority = auth.example\nGRPCMultiMode = true"},
		{"vmess-xhttp", vmessLink(`{"v":"2","add":"example.com","port":"443","id":"` + testUUID + `","net":"xhttp","path":"/x","mode":"packet-up","tls":"tls","alpn":"h2","extra":"{\"xPaddingBytes\":\"100-1000\"}"}`),
			"Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nNetwork = xhttp\nSecurity = tls\nALPN = h2\nXHTTPPath = /x\nXHTTPMode = packet-up\nXHTTPExtra = {\"xPaddingBytes\":\"100-1000\"}"},
		{"vmess-xhttp-defaults", vmessLink(`{"v":"2","add":"example.com","port":"443","id":"` + testUUID + `","net":"xhttp","tls":"tls"}`),
			"Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nNetwork = xhttp\nSecurity = tls"},
		{"vmess-reality", vmessLink(`{"v":"2","add":"example.com","port":"443","id":"` + testUUID + `","tls":"reality","sni":"front.example","fp":"chrome","pbk":"` + realityKey + `","sid":"abcd","spx":"/s"}`),
			"Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nSecurity = reality\nServerName = front.example\nFingerprint = chrome\nPublicKey = " + realityKey + "\nShortID = abcd\nSpiderX = /s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fromURI, explicit := resolveAccess(t, tc.uri), resolveAccess(t, tc.explicit)
			if !reflect.DeepEqual(fromURI, explicit) {
				t.Fatalf("explicit profile differs from URI:\nuri:      %+v\nexplicit: %+v", fromURI, explicit)
			}
		})
	}
}

func TestExplicitAccessRejectsForeignOptions(t *testing.T) {
	cases := []struct{ name, access, code, field string }{
		{"hysteria2-username", "Type = hysteria2\nServer = example.com\nPort = 443\nPassword = p\nUsername = alice", "option_not_supported", "Username"},
		{"hysteria2-network", "Type = hysteria2\nServer = example.com\nPort = 443\nPassword = p\nNetwork = ws", "option_not_supported", "Network"},
		{"hysteria2-password", "Type = hysteria2\nServer = example.com\nPort = 443", "value_required", "Password"},
		{"hysteria2-alpn", "Type = hysteria2\nServer = example.com\nPort = 443\nPassword = p\nALPN = h2", "alpn_invalid", "ALPN"},
		{"tuic-id", "Type = tuic\nServer = example.com\nPort = 443\nPassword = p", "uuid_invalid", "ID"},
		{"tuic-fingerprint", "Type = tuic\nServer = example.com\nPort = 443\nID = " + testUUID + "\nPassword = p\nFingerprint = chrome", "option_not_supported", "Fingerprint"},
		{"anytls-alpn", "Type = anytls\nServer = example.com\nPort = 443\nPassword = p\nALPN = h2", "option_not_supported", "ALPN"},
		{"anytls-xhttp", "Type = anytls\nServer = example.com\nPort = 443\nPassword = p\nXHTTPNoGRPCHeader = true", "option_not_supported", "XHTTPNoGRPCHeader"},
		{"vmess-password", "Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nSecurity = tls\nPassword = p", "option_not_supported", "Password"},
		{"vmess-flow", "Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nSecurity = tls\nFlow = xtls-rprx-vision", "option_not_supported", "Flow"},
		{"vmess-security", "Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID, "value_required", "Security"},
		{"vmess-encryption", "Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nSecurity = tls\nEncryption = none", "choice_invalid", "Encryption"},
		{"vmess-network", "Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nSecurity = tls\nNetwork = quic", "choice_invalid", "Network"},
		{"vmess-ws-path", "Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nSecurity = tls\nNetwork = ws\nWSPath = ws", "path_invalid", "WSPath"},
		{"vmess-grpc-service", "Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nSecurity = tls\nNetwork = grpc", "value_invalid", "GRPCServiceName"},
		{"vmess-grpc-on-tcp", "Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nSecurity = tls\nGRPCServiceName = svc", "option_requires_transport", "GRPCServiceName"},
		{"vmess-xhttp-mode", "Type = vmess\nServer = example.com\nPort = 443\nID = " + testUUID + "\nSecurity = tls\nNetwork = xhttp\nXHTTPMode = fast", "choice_invalid", "XHTTPMode"},
		{"naive-network", "Type = naive\nServer = example.com\nPort = 443\nUsername = alice\nPassword = p\nNetwork = ws", "choice_invalid", "Network"},
		{"naive-quic-flow", "Type = naive\nServer = example.com\nPort = 443\nUsername = alice\nPassword = p\nNetwork = quic\nFlow = xtls-rprx-vision", "option_not_supported", "Flow"},
		{"naive-alpn", "Type = naive\nServer = example.com\nPort = 443\nUsername = alice\nPassword = p\nALPN = h3", "option_not_supported", "ALPN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseData([]byte("[Profile]\nVersion = 1\n[AccessKey]\n" + tc.access + "\n"))
			p, ok := problem.As(err)
			if !ok || p.Code != tc.code || p.Field != tc.field || p.Section != "AccessKey" {
				t.Fatalf("got %#v (%v), want %s at %s", p, err, tc.code, tc.field)
			}
		})
	}
}

func TestExplicitNaiveDefaultsToHTTP2(t *testing.T) {
	p := resolveAccess(t, "Type = naive\nServer = example.com\nPort = 443\nUsername = alice\nPassword = secret")
	if p.Type != "naive" || p.Naive.QUIC {
		t.Fatalf("explicit Naive without Network must keep HTTP/2: %+v", p.Naive)
	}
}
