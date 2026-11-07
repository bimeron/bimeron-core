package accesskey

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"bimeron/internal/problem"
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

// Validate reports problems with the VMess link fields: Security is
// VMessSecurity, Network is VMessNetwork, TLS is VMessTLS, transport path,
// host and mode are VMessPath, VMessHost and VMessMode, XHTTP options are
// VMessExtra.
func (v VMess) Validate(host string, port int) error {
	if host == "" || strings.ContainsAny(host, " /\t\r\n") {
		return problem.New("host_invalid", "invalid VMess endpoint or user ID").At("Server")
	}
	if port < 1 || port > 65535 {
		return problem.New("port_invalid", "invalid VMess endpoint or user ID").At("Port")
	}
	if !uuidPattern.MatchString(v.ID) {
		return problem.New("uuid_invalid", "invalid VMess endpoint or user ID").On("ID", v.ID)
	}
	if v.Security != "auto" && v.Security != "aes-128-gcm" && v.Security != "chacha20-poly1305" {
		return problem.New("choice_invalid", "unsupported VMess encryption").At("VMessSecurity").Arg("allowed", "auto, aes-128-gcm, chacha20-poly1305")
	}
	if v.TLS != "tls" && v.TLS != "reality" {
		return problem.New("choice_invalid", "unsupported VMess transport").At("VMessTLS").Arg("allowed", "tls, reality")
	}
	if v.Network != "tcp" && v.Network != "ws" && v.Network != "httpupgrade" && v.Network != "grpc" && v.Network != "xhttp" {
		return problem.New("choice_invalid", "unsupported VMess transport").At("VMessNetwork").Arg("allowed", "tcp, ws, httpupgrade, grpc, xhttp")
	}
	if v.TLS == "reality" {
		const message = "invalid VMess REALITY settings"
		if v.Network != "tcp" && v.Network != "grpc" && v.Network != "xhttp" {
			return problem.New("combination_unsupported", message).At("VMessNetwork").Also("VMessTLS")
		}
		if v.Fingerprint == "" {
			return problem.New("value_required", message).On("Fingerprint", "")
		}
		if v.Network == "tcp" && v.ALPN != "" {
			return problem.New("combination_unsupported", message).At("ALPN").Also("VMessNetwork", "VMessTLS")
		}
		if v.Network == "xhttp" && v.XHTTPMode != "auto" && v.XHTTPMode != "stream-one" && v.XHTTPMode != "stream-up" {
			return problem.New("combination_unsupported", message).At("VMessMode").Also("VMessTLS")
		}
		key, err := base64.RawURLEncoding.DecodeString(v.PublicKey)
		if err != nil || len(key) != 32 {
			return problem.New("value_invalid", "invalid VMess REALITY key").At("PublicKey")
		}
		if len(v.ShortID) > 16 || len(v.ShortID)%2 != 0 {
			return problem.New("value_invalid", "invalid VMess REALITY key").At("ShortID")
		}
		if _, err := hex.DecodeString(v.ShortID); err != nil {
			return problem.New("value_invalid", "invalid VMess REALITY short ID").At("ShortID")
		}
	} else if field := firstSet("PublicKey", v.PublicKey, "ShortID", v.ShortID, "SpiderX", v.SpiderX); field != "" {
		return problem.New("option_requires_security", "REALITY options require VMess reality security").At(field).Also("VMessTLS").Arg("security", "REALITY")
	}
	if v.ServerName == "" || strings.ContainsAny(v.ServerName, " /\t\r\n") {
		return problem.New("server_name_invalid", "invalid VMess server name").At("ServerName")
	}
	for _, protocol := range strings.Split(v.ALPN, ",") {
		if v.ALPN == "" {
			break
		}
		if protocol == "" || strings.ContainsAny(protocol, " \t\r\n") {
			return problem.New("value_invalid", "invalid VMess ALPN").At("ALPN")
		}
		if (v.Network == "ws" || v.Network == "httpupgrade") && protocol != "http/1.1" {
			return problem.New("alpn_invalid", "invalid VMess ALPN").At("ALPN").Also("VMessNetwork").Arg("allowed", "http/1.1")
		}
		if v.Network == "grpc" && protocol != "h2" {
			return problem.New("alpn_invalid", "invalid VMess ALPN").At("ALPN").Also("VMessNetwork").Arg("allowed", "h2")
		}
		if v.Network == "xhttp" && protocol != "h2" && protocol != "h3" {
			return problem.New("alpn_invalid", "invalid VMess ALPN").At("ALPN").Also("VMessNetwork").Arg("allowed", "h2, h3")
		}
	}
	if v.Fingerprint != "" && !supportedFingerprint(v.Fingerprint) {
		return problem.New("fingerprint_unsupported", "unsupported VMess fingerprint").At("Fingerprint").Arg("allowed", fingerprints)
	}
	if v.Network == "tcp" && (v.WSPath != "" || v.WSHost != "") {
		return problem.New("option_requires_transport", "VMess HTTP options require ws or httpupgrade").At(firstSet("VMessPath", v.WSPath, "VMessHost", v.WSHost)).Also("VMessNetwork").Arg("transport", "ws, httpupgrade")
	}
	if v.Network == "ws" || v.Network == "httpupgrade" {
		path, err := url.ParseRequestURI(v.WSPath)
		if v.WSPath == "" || err != nil || path.IsAbs() || !strings.HasPrefix(v.WSPath, "/") || strings.ContainsAny(v.WSPath, "#\\ \t\r\n") {
			return problem.New("path_invalid", "invalid VMess WebSocket path").At("VMessPath")
		}
		if v.WSHost != "" {
			u, err := url.Parse("https://" + v.WSHost)
			if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || strings.ContainsAny(v.WSHost, " \t\r\n") {
				return problem.New("host_invalid", "invalid VMess WebSocket host").At("VMessHost")
			}
		}
	}
	multi := ""
	if v.GRPCMultiMode {
		multi = "multi"
	}
	if v.Network != "grpc" && (v.GRPCServiceName != "" || v.GRPCAuthority != "" || v.GRPCMultiMode) {
		return problem.New("option_requires_transport", "VMess gRPC options require grpc").At(firstSet("VMessPath", v.GRPCServiceName, "VMessHost", v.GRPCAuthority, "VMessMode", multi)).Also("VMessNetwork").Arg("transport", "grpc")
	}
	if v.Network == "grpc" {
		if v.GRPCServiceName == "" || strings.ContainsAny(v.GRPCServiceName, "?\\# \t\r\n") || (strings.Contains(v.GRPCServiceName, "/") && (!strings.HasPrefix(v.GRPCServiceName, "/") || strings.HasSuffix(v.GRPCServiceName, "/") || strings.Contains(v.GRPCServiceName, "//"))) {
			return problem.New("value_invalid", "invalid VMess gRPC settings").At("VMessPath")
		}
		if strings.ContainsAny(v.GRPCAuthority, " /\\@?#\t\r\n") || strings.HasPrefix(v.GRPCAuthority, ":") {
			return problem.New("host_invalid", "invalid VMess gRPC settings").At("VMessHost")
		}
	}
	extra := ""
	if v.XHTTPOptions != nil {
		extra = "set"
	}
	if v.Network != "xhttp" && (v.XHTTPPath != "" || v.XHTTPHost != "" || v.XHTTPMode != "" || v.XHTTPOptions != nil) {
		return problem.New("option_requires_transport", "VMess XHTTP options require xhttp").At(firstSet("VMessPath", v.XHTTPPath, "VMessHost", v.XHTTPHost, "VMessMode", v.XHTTPMode, "VMessExtra", extra)).Also("VMessNetwork").Arg("transport", "xhttp")
	}
	if v.Network == "xhttp" {
		if v.XHTTPMode != "auto" && v.XHTTPMode != "packet-up" && v.XHTTPMode != "stream-up" && v.XHTTPMode != "stream-one" {
			return problem.New("choice_invalid", "unsupported VMess XHTTP mode").At("VMessMode").Arg("allowed", "auto, packet-up, stream-up, stream-one")
		}
		if strings.Contains(v.ALPN, ",") {
			return problem.New("choice_invalid", "invalid VMess XHTTP ALPN").At("ALPN").Also("VMessNetwork").Arg("allowed", "h2, h3")
		}
		if v.ALPN == "h3" && v.Fingerprint != "" {
			return problem.New("combination_unsupported", "VMess HTTP/3 does not support TLS fingerprints").At("Fingerprint").Also("ALPN")
		}
		if v.ALPN == "h3" && v.TLS != "tls" {
			return problem.New("combination_unsupported", "VMess HTTP/3 does not support TLS fingerprints").At("VMessTLS").Also("ALPN")
		}
		if err := v.XHTTPOptions.Validate(v.XHTTPMode, v.TLS, v.ALPN); err != nil {
			return vmessXHTTPProblem(err)
		}
		path, err := url.ParseRequestURI(v.XHTTPPath)
		if v.XHTTPPath == "" || err != nil || path.IsAbs() || !strings.HasPrefix(v.XHTTPPath, "/") || strings.ContainsAny(v.XHTTPPath, "#\\ \t\r\n") {
			return problem.New("path_invalid", "invalid VMess XHTTP path").At("VMessPath")
		}
		if v.XHTTPHost != "" {
			u, err := url.Parse("https://" + v.XHTTPHost)
			if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" {
				return problem.New("host_invalid", "invalid VMess XHTTP host").At("VMessHost")
			}
		}
	}
	return nil
}

// firstSet takes name, value pairs and returns the first name with a value.
func firstSet(pairs ...string) string {
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			return pairs[i]
		}
	}
	return ""
}

// vmessXHTTPProblem renames the shared XHTTP fields to the VMess link fields.
func vmessXHTTPProblem(err error) error {
	p, ok := problem.As(err)
	if !ok {
		return err
	}
	p.Field = vmessField(p.Field)
	for i, field := range p.Related {
		p.Related[i] = vmessField(field)
	}
	return err
}

func vmessField(field string) string {
	switch {
	case field == "XHTTPMode":
		return "VMessMode"
	case field == "Security":
		return "VMessTLS"
	case strings.HasPrefix(field, "XHTTP"):
		return "VMessExtra"
	}
	return field
}

// ParseVMess accepts the common base64 JSON share format and never echoes secrets.
func ParseVMess(raw string) (Profile, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "vmess://") || len(raw) > maxBytes*2 {
		return Profile{}, problem.New("uri_invalid", "invalid VMess URI")
	}
	payload := strings.TrimPrefix(raw, "vmess://")
	if strings.ContainsAny(payload, "?# \t\r\n") {
		return Profile{}, problem.New("uri_invalid", "invalid VMess URI")
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
		return Profile{}, problem.New("uri_invalid", "invalid VMess payload")
	}
	fields := make(map[string]json.RawMessage)
	dec := json.NewDecoder(bytes.NewReader(decoded))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return Profile{}, problem.New("uri_invalid", "invalid VMess JSON")
	}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return Profile{}, problem.New("uri_invalid", "invalid VMess JSON")
		}
		key, ok := token.(string)
		if !ok || fields[key] != nil {
			return Profile{}, problem.New("uri_option_unsupported", "duplicate or invalid VMess field")
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return Profile{}, problem.New("uri_invalid", "invalid VMess JSON")
		}
		fields[key] = value
	}
	if _, err = dec.Token(); err != nil {
		return Profile{}, problem.New("uri_invalid", "invalid VMess JSON")
	}
	if _, err = dec.Token(); err != io.EOF {
		return Profile{}, problem.New("uri_invalid", "invalid VMess JSON")
	}
	allowed := map[string]bool{"v": true, "ps": true, "add": true, "port": true, "id": true, "aid": true, "scy": true, "net": true, "type": true, "host": true, "path": true, "tls": true, "sni": true, "alpn": true, "fp": true, "mode": true, "extra": true, "pbk": true, "sid": true, "spx": true}
	for k := range fields {
		if !allowed[k] {
			return Profile{}, problem.New("uri_option_unsupported", "unsupported VMess field")
		}
		var value string
		if json.Unmarshal(fields[k], &value) != nil {
			if k != "v" && k != "port" && k != "aid" {
				return Profile{}, problem.New("uri_invalid", "invalid VMess field type")
			}
			var number json.Number
			if json.Unmarshal(fields[k], &number) != nil {
				return Profile{}, problem.New("uri_invalid", "invalid VMess field type")
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
	const legacy = "unsupported VMess version or legacy authentication"
	if get("v") != "2" {
		return Profile{}, problem.New("vmess_legacy_unsupported", legacy).At("VMessVersion")
	}
	if get("aid") != "" && get("aid") != "0" {
		return Profile{}, problem.New("vmess_legacy_unsupported", legacy).At("AlterID")
	}
	if get("type") != "" && get("type") != "none" {
		return Profile{}, problem.New("vmess_legacy_unsupported", legacy).At("VMessHeaderType")
	}
	port, err := strconv.Atoi(get("port"))
	if err != nil {
		return Profile{}, problem.New("port_invalid", "invalid VMess port").At("Port")
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
			return Profile{}, problem.New("choice_invalid", "unsupported VMess gRPC mode").At("VMessMode").Arg("allowed", "multi")
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
				return Profile{}, vmessXHTTPProblem(err)
			}
		}
	} else if get("mode") != "" {
		return Profile{}, problem.New("option_requires_transport", "unsupported VMess mode").At("VMessMode").Also("VMessNetwork").Arg("transport", "grpc, xhttp")
	}
	if _, present := fields["extra"]; present && v.Network != "xhttp" {
		return Profile{}, problem.New("option_requires_transport", "VMess extra requires xhttp").At("VMessExtra").Also("VMessNetwork").Arg("transport", "xhttp")
	}
	if err := v.Validate(get("add"), port); err != nil {
		return Profile{}, err
	}
	e := Endpoint{Host: get("add"), Port: port}
	if net.ParseIP(e.Host) == nil && strings.ContainsAny(e.Host, ":@") {
		return Profile{}, problem.New("host_invalid", "invalid VMess endpoint").At("Server")
	}
	return Profile{Type: "vmess", Name: get("ps"), TCP: e, UDP: e, VMess: v}, nil
}
