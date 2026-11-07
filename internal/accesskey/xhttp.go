package accesskey

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"bimeron/internal/problem"
)

// XHTTPRange accepts Xray's integer or "from-to" JSON representation.
type XHTTPRange struct{ From, To int }

func (r *XHTTPRange) UnmarshalJSON(b []byte) error {
	var n int
	if json.Unmarshal(b, &n) == nil {
		r.From, r.To = n, n
		return nil
	}
	var s string
	if json.Unmarshal(b, &s) != nil {
		return problem.New("xhttp_extra_invalid", "invalid XHTTP range")
	}
	if n, err := strconv.Atoi(s); err == nil {
		r.From, r.To = n, n
		return nil
	}
	a, z, ok := strings.Cut(s, "-")
	if !ok {
		return problem.New("xhttp_extra_invalid", "invalid XHTTP range")
	}
	first, e1 := strconv.Atoi(a)
	last, e2 := strconv.Atoi(z)
	if e1 != nil || e2 != nil {
		return problem.New("xhttp_extra_invalid", "invalid XHTTP range")
	}
	r.From, r.To = min(first, last), max(first, last)
	return nil
}

func (r XHTTPRange) valid(minimum, maximum int) bool {
	return r.From >= minimum && r.To >= r.From && r.To <= maximum
}

type XHTTPXmux struct {
	MaxConcurrency   XHTTPRange `json:"maxConcurrency"`
	MaxConnections   XHTTPRange `json:"maxConnections"`
	CMaxReuseTimes   XHTTPRange `json:"cMaxReuseTimes"`
	HMaxRequestTimes XHTTPRange `json:"hMaxRequestTimes"`
	HMaxReusableSecs XHTTPRange `json:"hMaxReusableSecs"`
	HKeepAlivePeriod int        `json:"hKeepAlivePeriod"`
}

type XHTTPDownloadSettings struct {
	Address         string `json:"address"`
	Port            int    `json:"port"`
	Network         string `json:"network"`
	Security        string `json:"security"`
	ServerName      string `json:"serverName"`
	PublicKey       string `json:"publicKey"`
	ShortID         string `json:"shortId"`
	Fingerprint     string `json:"fingerprint"`
	ALPN            string `json:"alpn"`
	Host            string `json:"host"`
	Path            string `json:"path"`
	ResolvedAddress string `json:"-"`
}

// UnmarshalJSON accepts Xray's nested stream settings while keeping a flat
// internal representation for the transport code.
func (d *XHTTPDownloadSettings) UnmarshalJSON(data []byte) error {
	var wire struct {
		Address     string `json:"address"`
		Port        int    `json:"port"`
		Network     string `json:"network"`
		Security    string `json:"security"`
		TLSSettings *struct {
			ServerName  string   `json:"serverName"`
			ALPN        []string `json:"alpn"`
			Fingerprint string   `json:"fingerprint"`
		} `json:"tlsSettings"`
		RealitySettings *struct {
			ServerName  string `json:"serverName"`
			PublicKey   string `json:"publicKey"`
			ShortID     string `json:"shortId"`
			Fingerprint string `json:"fingerprint"`
		} `json:"realitySettings"`
		XHTTPSettings *struct {
			Host string `json:"host"`
			Path string `json:"path"`
		} `json:"xhttpSettings"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return problem.New("xhttp_extra_invalid", "invalid XHTTP download settings")
	}
	*d = XHTTPDownloadSettings{Address: wire.Address, Port: wire.Port, Network: wire.Network, Security: wire.Security}
	if wire.TLSSettings != nil {
		d.ServerName = wire.TLSSettings.ServerName
		d.Fingerprint = wire.TLSSettings.Fingerprint
		if len(wire.TLSSettings.ALPN) > 1 {
			return problem.New("xhttp_extra_invalid", "unsupported XHTTP download ALPN")
		}
		if len(wire.TLSSettings.ALPN) == 1 {
			d.ALPN = wire.TLSSettings.ALPN[0]
		}
	}
	if wire.RealitySettings != nil {
		if wire.TLSSettings != nil || wire.Security != "reality" {
			return problem.New("xhttp_extra_invalid", "invalid XHTTP download security settings")
		}
		d.ServerName, d.PublicKey, d.ShortID, d.Fingerprint = wire.RealitySettings.ServerName, wire.RealitySettings.PublicKey, wire.RealitySettings.ShortID, wire.RealitySettings.Fingerprint
	}
	if wire.XHTTPSettings != nil {
		d.Host, d.Path = wire.XHTTPSettings.Host, wire.XHTTPSettings.Path
	}
	return nil
}

type XHTTPOptions struct {
	Headers              map[string]string      `json:"headers"`
	XPaddingBytes        XHTTPRange             `json:"xPaddingBytes"`
	XPaddingObfsMode     bool                   `json:"xPaddingObfsMode"`
	XPaddingKey          string                 `json:"xPaddingKey"`
	XPaddingHeader       string                 `json:"xPaddingHeader"`
	XPaddingPlacement    string                 `json:"xPaddingPlacement"`
	XPaddingMethod       string                 `json:"xPaddingMethod"`
	UplinkHTTPMethod     string                 `json:"uplinkHTTPMethod"`
	SessionPlacement     string                 `json:"sessionPlacement"`
	SessionKey           string                 `json:"sessionKey"`
	SeqPlacement         string                 `json:"seqPlacement"`
	SeqKey               string                 `json:"seqKey"`
	UplinkDataPlacement  string                 `json:"uplinkDataPlacement"`
	UplinkDataKey        string                 `json:"uplinkDataKey"`
	UplinkChunkSize      XHTTPRange             `json:"uplinkChunkSize"`
	NoGRPCHeader         bool                   `json:"noGRPCHeader"`
	NoSSEHeader          bool                   `json:"noSSEHeader"`
	ScMaxEachPostBytes   XHTTPRange             `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs XHTTPRange             `json:"scMinPostsIntervalMs"`
	ScMaxBufferedPosts   int                    `json:"scMaxBufferedPosts"`
	ScStreamUpServerSecs XHTTPRange             `json:"scStreamUpServerSecs"`
	ServerMaxHeaderBytes int                    `json:"serverMaxHeaderBytes"`
	Xmux                 *XHTTPXmux             `json:"xmux"`
	DownloadSettings     *XHTTPDownloadSettings `json:"downloadSettings"`

	// separate records that the options came from separate XHTTP* .conf
	// options rather than one XHTTPExtra JSON value.
	separate bool
}

// field names the canonical option that holds the named setting.
func (o *XHTTPOptions) field(name string) string {
	if o.separate {
		return "XHTTP" + name
	}
	return "XHTTPExtra"
}

func ParseXHTTPExtra(raw string) (*XHTTPOptions, error) {
	if len(raw) > 16*1024 {
		return nil, problem.New("value_too_long", "XHTTP extra is too large").At("XHTTPExtra").Arg("max", "16384")
	}
	if err := xhttpCheckJSONKeys(json.NewDecoder(strings.NewReader(raw))); err != nil {
		return nil, problem.New("xhttp_extra_invalid", "invalid or duplicate XHTTP extra key").At("XHTTPExtra")
	}
	var options XHTTPOptions
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&options) != nil || d.Decode(new(any)) != io.EOF || !strings.HasPrefix(strings.TrimSpace(raw), "{") {
		return nil, problem.New("xhttp_extra_invalid", "invalid or unsupported XHTTP extra").At("XHTTPExtra")
	}
	return &options, nil
}

func xhttpCheckJSONKeys(d *json.Decoder) error {
	var value func() error
	value = func() error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		start, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if start == '[' {
			for d.More() {
				if err := value(); err != nil {
					return err
				}
			}
		} else if start == '{' {
			seen := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate JSON key")
				}
				seen[key] = true
				if err := value(); err != nil {
					return err
				}
			}
		} else {
			return fmt.Errorf("invalid JSON")
		}
		_, err = d.Token()
		return err
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

var xhttpToken = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]+$`)

// Validate checks the options against the XHTTP mode, security and ALPN.
// Problems name XHTTPExtra or the separate XHTTP* option, with XHTTPMode,
// Security and ALPN as related fields.
func (o *XHTTPOptions) Validate(mode, security, alpn string) error {
	if o == nil {
		return nil
	}
	for name, value := range o.Headers {
		if !xhttpToken.MatchString(name) || strings.EqualFold(name, "host") || strings.ContainsAny(value, "\r\n") || len(value) > 4096 {
			return problem.New("xhttp_header_invalid", "invalid XHTTP header").At(o.field("Headers"))
		}
	}
	for _, r := range []struct {
		name  string
		value XHTTPRange
	}{{"XPaddingBytes", o.XPaddingBytes}, {"UplinkChunkSize", o.UplinkChunkSize}, {"ScMaxEachPostBytes", o.ScMaxEachPostBytes}, {"ScMinPostsIntervalMs", o.ScMinPostsIntervalMs}, {"ScStreamUpServerSecs", o.ScStreamUpServerSecs}} {
		if r.value != (XHTTPRange{}) && !r.value.valid(1, 1<<20) {
			return problem.New("xhttp_range_invalid", "invalid XHTTP range").At(o.field(r.name)).Arg("min", "1").Arg("max", "1048576")
		}
	}
	if o.ScMaxBufferedPosts < 0 || o.ScMaxBufferedPosts > 1024 {
		return problem.New("number_out_of_range", "invalid XHTTP limit").At(o.field("ScMaxBufferedPosts")).Arg("min", "0").Arg("max", "1024")
	}
	if o.ServerMaxHeaderBytes < 0 || o.ServerMaxHeaderBytes > 1<<20 {
		return problem.New("number_out_of_range", "invalid XHTTP limit").At(o.field("ServerMaxHeaderBytes")).Arg("min", "0").Arg("max", "1048576")
	}
	if o.XPaddingPlacement != "" && o.XPaddingPlacement != "queryInHeader" && o.XPaddingPlacement != "query" && o.XPaddingPlacement != "header" && o.XPaddingPlacement != "cookie" {
		return problem.New("choice_invalid", "invalid XHTTP padding placement").At(o.field("XPaddingPlacement")).Arg("allowed", "queryInHeader, query, header, cookie")
	}
	if o.XPaddingMethod != "" && o.XPaddingMethod != "repeat-x" && o.XPaddingMethod != "tokenish" {
		return problem.New("choice_invalid", "invalid XHTTP padding method").At(o.field("XPaddingMethod")).Arg("allowed", "repeat-x, tokenish")
	}
	for _, key := range []struct{ name, value string }{{"XPaddingKey", o.XPaddingKey}, {"XPaddingHeader", o.XPaddingHeader}, {"SessionKey", o.SessionKey}, {"SeqKey", o.SeqKey}, {"UplinkDataKey", o.UplinkDataKey}} {
		if key.value != "" && !xhttpToken.MatchString(key.value) {
			return problem.New("value_has_invalid_characters", "invalid XHTTP key").At(o.field(key.name))
		}
	}
	for _, placement := range []struct{ name, value string }{{"SessionPlacement", o.SessionPlacement}, {"SeqPlacement", o.SeqPlacement}} {
		if placement.value != "" && placement.value != "path" && placement.value != "query" && placement.value != "header" && placement.value != "cookie" {
			return problem.New("choice_invalid", "invalid XHTTP metadata placement").At(o.field(placement.name)).Arg("allowed", "path, query, header, cookie")
		}
	}
	if o.UplinkDataPlacement != "" && o.UplinkDataPlacement != "auto" && o.UplinkDataPlacement != "body" && o.UplinkDataPlacement != "header" && o.UplinkDataPlacement != "cookie" {
		return problem.New("choice_invalid", "invalid XHTTP uplink data placement").At(o.field("UplinkDataPlacement")).Arg("allowed", "auto, body, header, cookie")
	}
	if (o.UplinkDataPlacement == "header" || o.UplinkDataPlacement == "cookie") && mode != "packet-up" {
		return problem.New("option_requires_mode", "XHTTP uplink placement requires packet-up").At(o.field("UplinkDataPlacement")).Also("XHTTPMode").Arg("mode", "packet-up")
	}
	if o.UplinkHTTPMethod != "" && o.UplinkHTTPMethod != "POST" && o.UplinkHTTPMethod != "GET" {
		return problem.New("choice_invalid", "invalid XHTTP uplink method").At(o.field("UplinkHTTPMethod")).Arg("allowed", "POST, GET")
	}
	if o.UplinkHTTPMethod == "GET" && mode != "packet-up" {
		return problem.New("option_requires_mode", "invalid XHTTP uplink method").At(o.field("UplinkHTTPMethod")).Also("XHTTPMode").Arg("mode", "packet-up")
	}
	if o.Xmux != nil {
		m := o.Xmux
		for _, r := range []XHTTPRange{m.MaxConcurrency, m.MaxConnections, m.CMaxReuseTimes, m.HMaxRequestTimes, m.HMaxReusableSecs} {
			if r != (XHTTPRange{}) && !r.valid(1, 100000) {
				return problem.New("xhttp_range_invalid", "invalid XHTTP xmux range").At(o.field("Xmux")).Arg("min", "1").Arg("max", "100000")
			}
		}
		if m.MaxConcurrency != (XHTTPRange{}) && m.MaxConnections != (XHTTPRange{}) {
			return problem.New("combination_unsupported", "unsupported XHTTP xmux settings").At(o.field("Xmux"))
		}
		if m.HKeepAlivePeriod < 0 || m.HKeepAlivePeriod > 86400 {
			return problem.New("number_out_of_range", "unsupported XHTTP xmux settings").At(o.field("Xmux")).Arg("min", "0").Arg("max", "86400")
		}
		if alpn == "h3" {
			return problem.New("combination_unsupported", "unsupported XHTTP xmux settings").At(o.field("Xmux")).Also("ALPN")
		}
	}
	if d := o.DownloadSettings; d != nil {
		field := o.field("DownloadSettings")
		if mode == "stream-one" {
			return problem.New("combination_unsupported", "invalid XHTTP download settings").At(field).Also("XHTTPMode")
		}
		if mode == "auto" && security == "reality" {
			return problem.New("combination_unsupported", "invalid XHTTP download settings").At(field).Also("XHTTPMode", "Security")
		}
		if d.Address == "" || d.Port < 1 || d.Port > 65535 || d.Network != "xhttp" || (d.Security != "tls" && d.Security != "reality") {
			return problem.New("xhttp_download_invalid", "invalid XHTTP download settings").At(field)
		}
		if strings.ContainsAny(d.Address, " /\\@?#\t\r\n") || strings.ContainsAny(d.ServerName, " /\\@?#\t\r\n") || strings.ContainsAny(d.Host, "\r\n") || strings.ContainsAny(d.Path, "\r\n") {
			return problem.New("xhttp_download_invalid", "invalid XHTTP download endpoint").At(field)
		}
		if d.Security == "reality" {
			if d.ServerName == "" || d.Fingerprint == "" || d.PublicKey == "" || d.ALPN == "h3" {
				return problem.New("xhttp_download_invalid", "invalid XHTTP download REALITY settings").At(field)
			}
			key, err := base64.RawURLEncoding.DecodeString(d.PublicKey)
			if err != nil || len(key) != 32 || len(d.ShortID) > 16 || len(d.ShortID)%2 != 0 {
				return problem.New("xhttp_download_invalid", "invalid XHTTP download REALITY key").At(field)
			}
			if _, err := hex.DecodeString(d.ShortID); err != nil {
				return problem.New("xhttp_download_invalid", "invalid XHTTP download REALITY short ID").At(field)
			}
			if !supportedFingerprint(d.Fingerprint) {
				return problem.New("fingerprint_unsupported", "unsupported XHTTP download fingerprint").At(field).Arg("allowed", fingerprints)
			}
		} else if d.PublicKey != "" || d.ShortID != "" {
			return problem.New("xhttp_download_invalid", "REALITY options require download security=reality").At(field)
		}
		if d.ALPN != "" && d.ALPN != "h2" && d.ALPN != "h3" {
			return problem.New("alpn_invalid", "invalid XHTTP download ALPN").At(field).Arg("allowed", "h2, h3")
		}
		if d.ALPN == "h3" && d.Fingerprint != "" {
			return problem.New("combination_unsupported", "invalid XHTTP download ALPN").At(field)
		}
		if d.Fingerprint != "" && !supportedFingerprint(d.Fingerprint) {
			return problem.New("fingerprint_unsupported", "unsupported XHTTP download fingerprint").At(field).Arg("allowed", fingerprints)
		}
		if d.Host != "" {
			host, err := url.Parse("https://" + d.Host)
			if err != nil || host.Hostname() == "" || host.User != nil || host.Path != "" || host.RawQuery != "" || host.Fragment != "" || strings.ContainsAny(d.Host, " /\\@?#\t\r\n") {
				return problem.New("host_invalid", "invalid XHTTP download host").At(field)
			}
		}
		if d.Path != "" && (!strings.HasPrefix(d.Path, "/") || strings.ContainsAny(d.Path, "#\\")) {
			return problem.New("path_invalid", "invalid XHTTP download path").At(field)
		}
	}
	return nil
}

// fingerprints lists the supported TLS fingerprints for problem arguments.
const fingerprints = "chrome, firefox, safari, ios, android, edge"

func supportedFingerprint(name string) bool {
	switch name {
	case "chrome", "firefox", "safari", "ios", "android", "edge":
		return true
	}
	return false
}

// SetXHTTPConfField maps simple .conf fields to the same model as link extra.
func (o *XHTTPOptions) SetXHTTPConfField(key, value string) error {
	field := strings.TrimPrefix(key, "XHTTP")
	if field == "" {
		return problem.New("option_unknown", "unknown XHTTP option").At(key)
	}
	name := strings.ToLower(field[:1]) + field[1:]
	target := reflect.ValueOf(o).Elem().FieldByName(field)
	if !target.IsValid() || !target.CanSet() {
		return problem.New("option_unknown", "unknown XHTTP option").At(key)
	}
	var raw json.RawMessage
	switch {
	case target.Kind() == reflect.Bool:
		if value != "true" && value != "false" {
			return problem.New("boolean_invalid", "invalid XHTTP boolean").At(key)
		}
		raw = []byte(value)
	case target.Kind() == reflect.Int || target.Type() == reflect.TypeOf(XHTTPRange{}):
		if _, err := strconv.Atoi(value); err == nil {
			raw = []byte(value)
		} else {
			raw, _ = json.Marshal(value)
		}
	case target.Kind() == reflect.Map || target.Kind() == reflect.Ptr:
		raw = []byte(value)
	default:
		raw, _ = json.Marshal(value)
	}
	data, _ := json.Marshal(map[string]json.RawMessage{name: raw})
	parsed, err := ParseXHTTPExtra(string(data))
	if err != nil {
		if p, ok := problem.As(err); ok {
			p.At(key)
		}
		return err
	}
	target.Set(reflect.ValueOf(parsed).Elem().FieldByName(field))
	o.separate = true
	return nil
}
