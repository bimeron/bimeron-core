package accesskey

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// VMess describes the supported VMess AEAD client settings.
type VMess struct {
	ID, Security, Network, TLS, ServerName, WSPath, WSHost string
	ALPN, Fingerprint                                      string
}

func (v VMess) Validate(host string, port int) error {
	if host == "" || strings.ContainsAny(host, " /\t\r\n") || port < 1 || port > 65535 || !uuidPattern.MatchString(v.ID) {
		return fmt.Errorf("invalid VMess endpoint or user ID")
	}
	if v.Security != "auto" && v.Security != "aes-128-gcm" && v.Security != "chacha20-poly1305" {
		return fmt.Errorf("unsupported VMess encryption")
	}
	if v.TLS != "tls" || (v.Network != "tcp" && v.Network != "ws") {
		return fmt.Errorf("unsupported VMess transport")
	}
	if v.ServerName == "" || strings.ContainsAny(v.ServerName, " /\t\r\n") {
		return fmt.Errorf("invalid VMess server name")
	}
	for _, protocol := range strings.Split(v.ALPN, ",") {
		if v.ALPN != "" && (protocol == "" || strings.ContainsAny(protocol, " \t\r\n") || (v.Network == "ws" && protocol != "http/1.1")) {
			return fmt.Errorf("invalid VMess ALPN")
		}
	}
	if v.Fingerprint != "" {
		switch v.Fingerprint {
		case "chrome", "firefox", "safari", "ios", "android", "edge":
		default:
			return fmt.Errorf("unsupported VMess fingerprint")
		}
	}
	if v.Network != "ws" && (v.WSPath != "" || v.WSHost != "") {
		return fmt.Errorf("VMess WebSocket options require ws")
	}
	if v.Network == "ws" {
		path, err := url.ParseRequestURI(v.WSPath)
		if v.WSPath == "" || err != nil || path.IsAbs() || !strings.HasPrefix(v.WSPath, "/") || strings.ContainsAny(v.WSPath, "#\\ \t\r\n") {
			return fmt.Errorf("invalid VMess WebSocket path")
		}
		if v.WSHost != "" {
			u, err := url.Parse("https://" + v.WSHost)
			if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || strings.ContainsAny(v.WSHost, " \t\r\n") {
				return fmt.Errorf("invalid VMess WebSocket host")
			}
		}
	}
	return nil
}

// ParseVMess accepts the common base64 JSON share format and never echoes secrets.
func ParseVMess(raw string) (Profile, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "vmess://") || len(raw) > maxBytes*2 {
		return Profile{}, fmt.Errorf("invalid VMess URI")
	}
	payload := strings.TrimPrefix(raw, "vmess://")
	if strings.ContainsAny(payload, "?# \t\r\n") {
		return Profile{}, fmt.Errorf("invalid VMess URI")
	}
	var decoded []byte
	var err error
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err = encoding.DecodeString(payload)
		if err == nil {
			break
		}
	}
	if err != nil || len(decoded) > maxBytes {
		return Profile{}, fmt.Errorf("invalid VMess payload")
	}
	fields := make(map[string]json.RawMessage)
	dec := json.NewDecoder(bytes.NewReader(decoded))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return Profile{}, fmt.Errorf("invalid VMess JSON")
	}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return Profile{}, fmt.Errorf("invalid VMess JSON")
		}
		key, ok := token.(string)
		if !ok || fields[key] != nil {
			return Profile{}, fmt.Errorf("duplicate or invalid VMess field")
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return Profile{}, fmt.Errorf("invalid VMess JSON")
		}
		fields[key] = value
	}
	if _, err = dec.Token(); err != nil {
		return Profile{}, fmt.Errorf("invalid VMess JSON")
	}
	if _, err = dec.Token(); err != io.EOF {
		return Profile{}, fmt.Errorf("invalid VMess JSON")
	}
	allowed := map[string]bool{"v": true, "ps": true, "add": true, "port": true, "id": true, "aid": true, "scy": true, "net": true, "type": true, "host": true, "path": true, "tls": true, "sni": true, "alpn": true, "fp": true}
	for k := range fields {
		if !allowed[k] {
			return Profile{}, fmt.Errorf("unsupported VMess field")
		}
		var value string
		if json.Unmarshal(fields[k], &value) != nil {
			if k != "v" && k != "port" && k != "aid" {
				return Profile{}, fmt.Errorf("invalid VMess field type")
			}
			var number json.Number
			if json.Unmarshal(fields[k], &number) != nil {
				return Profile{}, fmt.Errorf("invalid VMess field type")
			}
		}
	}
	get := func(k string) string {
		var s string
		if json.Unmarshal(fields[k], &s) == nil {
			return s
		}
		var n json.Number
		if json.Unmarshal(fields[k], &n) == nil {
			return string(n)
		}
		return ""
	}
	if get("v") != "2" || (get("aid") != "" && get("aid") != "0") || (get("type") != "" && get("type") != "none") {
		return Profile{}, fmt.Errorf("unsupported VMess version or legacy authentication")
	}
	port, err := strconv.Atoi(get("port"))
	if err != nil {
		return Profile{}, fmt.Errorf("invalid VMess port")
	}
	v := VMess{ID: get("id"), Security: get("scy"), Network: get("net"), TLS: get("tls"), ServerName: get("sni"), WSPath: get("path"), WSHost: get("host"), ALPN: get("alpn"), Fingerprint: get("fp")}
	if v.Security == "" {
		v.Security = "auto"
	}
	if v.Network == "" {
		v.Network = "tcp"
	}
	if v.ServerName == "" {
		v.ServerName = get("add")
	}
	if v.Network == "ws" && v.WSPath == "" {
		v.WSPath = "/"
	}
	if err := v.Validate(get("add"), port); err != nil {
		return Profile{}, err
	}
	e := Endpoint{Host: get("add"), Port: port}
	if net.ParseIP(e.Host) == nil && strings.ContainsAny(e.Host, ":@") {
		return Profile{}, fmt.Errorf("invalid VMess endpoint")
	}
	return Profile{Type: "vmess", Name: get("ps"), TCP: e, UDP: e, VMess: v}, nil
}
