package accesskey

import "testing"

// Every access-key URI parser must accept or reject arbitrary text without
// panicking; each one sees every input, not only its own scheme.
func FuzzParseURI(f *testing.F) {
	for _, seed := range []string{
		"ss://YWVzLTI1Ni1nY206cHc@127.0.0.1:443#name",
		"vless://11111111-1111-1111-1111-111111111111@example.com:443?type=ws&security=tls&sni=example.com&path=%2F",
		"vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=tls&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D",
		"vmess://eyJ2IjoiMiIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMTExMS0xMTExLTExMTEtMTExMTExMTExMTExIn0=",
		"trojan://password@example.com:443?sni=example.com",
		"hysteria2://password@example.com:443?sni=example.com",
		"hy2://password@example.com:443?obfs=salamander&obfs-password=x",
		"tuic://11111111-1111-1111-1111-111111111111:password@example.com:443?sni=example.com",
		"anytls://password@example.com:443?sni=example.com",
		"ssh://user@example.com:22",
		"masque://user:password@example.com:443",
		"naive+https://user:password@example.com:443",
		"http://user:password@example.com:8080",
		"socks5://user:password@example.com:1080",
		`{"xPaddingBytes":"100-1000","noGRPCHeader":true}`,
	} {
		f.Add(seed)
	}
	parsers := []func(string) (Profile, error){ParseAnyTLS, ParseSSH, ParseTrojan, ParseVLESS, ParseSS, ParseHTTPConnect, ParseMASQUE, ParseNaive, ParseTUIC, ParseVMess, ParseHysteria2, ParseSOCKS5}
	f.Fuzz(func(t *testing.T, raw string) {
		for _, parse := range parsers {
			_, _ = parse(raw)
		}
		_, _ = ParseXHTTPExtra(raw)
	})
}

// SSConf responses come from a remote server.
func FuzzParseConfig(f *testing.F) {
	for _, seed := range []string{
		"ss://YWVzLTI1Ni1nY206cHc@127.0.0.1:443",
		"server: 127.0.0.1\nserver_port: 443\nmethod: aes-128-gcm\npassword: secret\n",
		`{"server":"example.com","server_port":443,"method":"chacha20-ietf-poly1305","password":"secret"}`,
		"a: &x [*x, *x]\n",
		"transport:\n  $type: tcpudp\n  tcp: &shared\n    $type: shadowsocks\n    endpoint: example.com:8388\n    cipher: aes-256-gcm\n    secret: secret\n  udp:\n    <<: *shared\n",
		"server: example.com\nserver_port: 8388\nmethod: aes-256-gcm\npassword: secret\nplugin: v2ray-plugin\nplugin_opts: tls;host=ws.example;mux=8\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseConfig(b)
	})
}

func FuzzParseSSPlugin(f *testing.F) {
	f.Add("v2ray-plugin", "tls;host=example.com;path=/;mux=4")
	f.Add("obfs-local", "obfs=http;obfs-host=example.com")
	f.Fuzz(func(t *testing.T, name, options string) {
		_, _ = ParseSSPlugin(name, options)
	})
}
