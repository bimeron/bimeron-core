package accesskey

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
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
	GRPCServiceName, GRPCAuthority                         string
	GRPCMultiMode                                          bool
	XHTTPPath, XHTTPHost, XHTTPMode                        string
	XHTTPOptions                                           *XHTTPOptions
	PublicKey, ShortID, SpiderX                            string
}

func (v VMess) Validate(host string, port int) error {
	if host == "" || strings.ContainsAny(host, " /\t\r\n") || port < 1 || port > 65535 || !uuidPattern.MatchString(v.ID) {
		return fmt.Errorf("invalid VMess endpoint or user ID")
	}
	if v.Security != "auto" && v.Security != "aes-128-gcm" && v.Security != "chacha20-poly1305" {
		return fmt.Errorf("unsupported VMess encryption")
	}
	if (v.TLS != "tls" && v.TLS != "reality") || (v.Network != "tcp" && v.Network != "ws" && v.Network != "httpupgrade" && v.Network != "grpc" && v.Network != "xhttp") {
		return fmt.Errorf("unsupported VMess transport")
	}
	if v.TLS == "reality" {
		if v.Network != "tcp" && v.Network != "grpc" && v.Network != "xhttp" || v.Fingerprint == "" || (v.Network == "tcp" && v.ALPN != "") || (v.Network == "xhttp" && v.XHTTPMode != "auto" && v.XHTTPMode != "stream-one" && v.XHTTPMode != "stream-up") {
			return fmt.Errorf("invalid VMess REALITY settings")
		}
		key, err := base64.RawURLEncoding.DecodeString(v.PublicKey)
		if err != nil || len(key) != 32 || len(v.ShortID) > 16 || len(v.ShortID)%2 != 0 {
			return fmt.Errorf("invalid VMess REALITY key")
		}
		if _, err := hex.DecodeString(v.ShortID); err != nil {
			return fmt.Errorf("invalid VMess REALITY short ID")
		}
	} else if v.PublicKey != "" || v.ShortID != "" || v.SpiderX != "" {
		return fmt.Errorf("REALITY options require VMess reality security")
	}
	if v.ServerName == "" || strings.ContainsAny(v.ServerName, " /\t\r\n") {
		return fmt.Errorf("invalid VMess server name")
	}
	for _, protocol := range strings.Split(v.ALPN, ",") {
		if v.ALPN != "" && (protocol == "" || strings.ContainsAny(protocol, " \t\r\n") || ((v.Network == "ws" || v.Network == "httpupgrade") && protocol != "http/1.1") || (v.Network == "grpc" && protocol != "h2") || (v.Network == "xhttp" && protocol != "h2" && protocol != "h3")) {
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
	if v.Network == "tcp" && (v.WSPath != "" || v.WSHost != "") {
		return fmt.Errorf("VMess HTTP options require ws or httpupgrade")
	}
	if v.Network == "ws" || v.Network == "httpupgrade" {
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
	if v.Network != "grpc" && (v.GRPCServiceName != "" || v.GRPCAuthority != "" || v.GRPCMultiMode) {
		return fmt.Errorf("VMess gRPC options require grpc")
	}
	if v.Network == "grpc" && (v.GRPCServiceName == "" || strings.ContainsAny(v.GRPCServiceName, "?\\# \t\r\n") || (strings.Contains(v.GRPCServiceName, "/") && (!strings.HasPrefix(v.GRPCServiceName, "/") || strings.HasSuffix(v.GRPCServiceName, "/") || strings.Contains(v.GRPCServiceName, "//"))) || strings.ContainsAny(v.GRPCAuthority, " /\\@?#\t\r\n") || strings.HasPrefix(v.GRPCAuthority, ":")) {
		return fmt.Errorf("invalid VMess gRPC settings")
	}
	if v.Network != "xhttp" && (v.XHTTPPath != "" || v.XHTTPHost != "" || v.XHTTPMode != "" || v.XHTTPOptions != nil) {
		return fmt.Errorf("VMess XHTTP options require xhttp")
	}
	if v.Network == "xhttp" {
		if v.XHTTPMode != "auto" && v.XHTTPMode != "packet-up" && v.XHTTPMode != "stream-up" && v.XHTTPMode != "stream-one" {
			return fmt.Errorf("unsupported VMess XHTTP mode")
		}
		if strings.Contains(v.ALPN, ",") {
			return fmt.Errorf("invalid VMess XHTTP ALPN")
		}
		if v.ALPN == "h3" && (v.Fingerprint != "" || v.TLS != "tls") {
			return fmt.Errorf("VMess HTTP/3 does not support TLS fingerprints")
		}
		if err := v.XHTTPOptions.Validate(v.XHTTPMode, v.TLS, v.ALPN); err != nil {
			return err
		}
		path, err := url.ParseRequestURI(v.XHTTPPath)
		if v.XHTTPPath == "" || err != nil || path.IsAbs() || !strings.HasPrefix(v.XHTTPPath, "/") || strings.ContainsAny(v.XHTTPPath, "#\\ \t\r\n") {
			return fmt.Errorf("invalid VMess XHTTP path")
		}
		if v.XHTTPHost != "" {
			u, err := url.Parse("https://" + v.XHTTPHost)
			if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" {
				return fmt.Errorf("invalid VMess XHTTP host")
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
	allowed := map[string]bool{"v": true, "ps": true, "add": true, "port": true, "id": true, "aid": true, "scy": true, "net": true, "type": true, "host": true, "path": true, "tls": true, "sni": true, "alpn": true, "fp": true, "mode": true, "extra": true, "pbk": true, "sid": true, "spx": true}
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
	v := VMess{ID: get("id"), Security: get("scy"), Network: get("net"), TLS: get("tls"), ServerName: get("sni"), WSPath: get("path"), WSHost: get("host"), ALPN: get("alpn"), Fingerprint: get("fp"), PublicKey: get("pbk"), ShortID: get("sid"), SpiderX: get("spx")}
	if v.Security == "" {
		v.Security = "auto"
	}
	if v.Network == "" {
		v.Network = "tcp"
	}
	if v.ServerName == "" {
		v.ServerName = get("add")
	}
	if (v.Network == "ws" || v.Network == "httpupgrade") && v.WSPath == "" {
		v.WSPath = "/"
	}
	if v.Network == "grpc" {
		v.GRPCServiceName, v.GRPCAuthority = get("path"), get("host")
		v.WSPath, v.WSHost = "", ""
		v.GRPCMultiMode = get("mode") == "multi"
		if get("mode") != "" && get("mode") != "multi" {
			return Profile{}, fmt.Errorf("unsupported VMess gRPC mode")
		}
	} else if v.Network == "xhttp" {
		v.XHTTPPath, v.XHTTPHost, v.XHTTPMode = get("path"), get("host"), get("mode")
		v.WSPath, v.WSHost = "", ""
		if v.XHTTPPath == "" {
			v.XHTTPPath = "/"
		}
		if v.XHTTPMode == "" {
			v.XHTTPMode = "auto"
		}
		if _, present := fields["extra"]; present {
			v.XHTTPOptions, err = ParseXHTTPExtra(get("extra"))
			if err != nil {
				return Profile{}, err
			}
		}
	} else if get("mode") != "" {
		return Profile{}, fmt.Errorf("unsupported VMess mode")
	}
	if _, present := fields["extra"]; present && v.Network != "xhttp" {
		return Profile{}, fmt.Errorf("VMess extra requires xhttp")
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
