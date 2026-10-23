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
		return fmt.Errorf("invalid XHTTP range")
	}
	if n, err := strconv.Atoi(s); err == nil {
		r.From, r.To = n, n
		return nil
	}
	a, z, ok := strings.Cut(s, "-")
	if !ok {
		return fmt.Errorf("invalid XHTTP range")
	}
	first, e1 := strconv.Atoi(a)
	last, e2 := strconv.Atoi(z)
	if e1 != nil || e2 != nil {
		return fmt.Errorf("invalid XHTTP range")
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
		return fmt.Errorf("invalid XHTTP download settings")
	}
	*d = XHTTPDownloadSettings{Address: wire.Address, Port: wire.Port, Network: wire.Network, Security: wire.Security}
	if wire.TLSSettings != nil {
		d.ServerName = wire.TLSSettings.ServerName
		d.Fingerprint = wire.TLSSettings.Fingerprint
		if len(wire.TLSSettings.ALPN) > 1 {
			return fmt.Errorf("unsupported XHTTP download ALPN")
		}
		if len(wire.TLSSettings.ALPN) == 1 {
			d.ALPN = wire.TLSSettings.ALPN[0]
		}
	}
	if wire.RealitySettings != nil {
		if wire.TLSSettings != nil || wire.Security != "reality" {
			return fmt.Errorf("invalid XHTTP download security settings")
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
}

func ParseXHTTPExtra(raw string) (*XHTTPOptions, error) {
	if len(raw) > 16*1024 {
		return nil, fmt.Errorf("XHTTP extra is too large")
	}
	if err := xhttpCheckJSONKeys(json.NewDecoder(strings.NewReader(raw))); err != nil {
		return nil, fmt.Errorf("invalid or duplicate XHTTP extra key")
	}
	var options XHTTPOptions
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&options) != nil || d.Decode(new(any)) != io.EOF || !strings.HasPrefix(strings.TrimSpace(raw), "{") {
		return nil, fmt.Errorf("invalid or unsupported XHTTP extra")
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

func (o *XHTTPOptions) Validate(mode, security, alpn string) error {
	if o == nil {
		return nil
	}
	for name, value := range o.Headers {
		if !xhttpToken.MatchString(name) || strings.EqualFold(name, "host") || strings.ContainsAny(value, "\r\n") || len(value) > 4096 {
			return fmt.Errorf("invalid XHTTP header")
		}
	}
	for _, r := range []XHTTPRange{o.XPaddingBytes, o.UplinkChunkSize, o.ScMaxEachPostBytes, o.ScMinPostsIntervalMs, o.ScStreamUpServerSecs} {
		if r != (XHTTPRange{}) && !r.valid(1, 1<<20) {
			return fmt.Errorf("invalid XHTTP range")
		}
	}
	if o.ScMaxBufferedPosts < 0 || o.ScMaxBufferedPosts > 1024 || o.ServerMaxHeaderBytes < 0 || o.ServerMaxHeaderBytes > 1<<20 {
		return fmt.Errorf("invalid XHTTP limit")
	}
	if o.XPaddingPlacement != "" && o.XPaddingPlacement != "queryInHeader" && o.XPaddingPlacement != "query" && o.XPaddingPlacement != "header" && o.XPaddingPlacement != "cookie" {
		return fmt.Errorf("invalid XHTTP padding placement")
	}
	if o.XPaddingMethod != "" && o.XPaddingMethod != "repeat-x" && o.XPaddingMethod != "tokenish" {
		return fmt.Errorf("invalid XHTTP padding method")
	}
	for _, key := range []string{o.XPaddingKey, o.XPaddingHeader, o.SessionKey, o.SeqKey, o.UplinkDataKey} {
		if key != "" && !xhttpToken.MatchString(key) {
			return fmt.Errorf("invalid XHTTP key")
		}
	}
	for _, placement := range []string{o.SessionPlacement, o.SeqPlacement} {
		if placement != "" && placement != "path" && placement != "query" && placement != "header" && placement != "cookie" {
			return fmt.Errorf("invalid XHTTP metadata placement")
		}
	}
	if o.UplinkDataPlacement != "" && o.UplinkDataPlacement != "auto" && o.UplinkDataPlacement != "body" && o.UplinkDataPlacement != "header" && o.UplinkDataPlacement != "cookie" {
		return fmt.Errorf("invalid XHTTP uplink data placement")
	}
	if (o.UplinkDataPlacement == "header" || o.UplinkDataPlacement == "cookie") && mode != "packet-up" {
		return fmt.Errorf("XHTTP uplink placement requires packet-up")
	}
	if o.UplinkHTTPMethod != "" && o.UplinkHTTPMethod != "POST" && (o.UplinkHTTPMethod != "GET" || mode != "packet-up") {
		return fmt.Errorf("invalid XHTTP uplink method")
	}
	if o.Xmux != nil {
		m := o.Xmux
		for _, r := range []XHTTPRange{m.MaxConcurrency, m.MaxConnections, m.CMaxReuseTimes, m.HMaxRequestTimes, m.HMaxReusableSecs} {
			if r != (XHTTPRange{}) && !r.valid(1, 100000) {
				return fmt.Errorf("invalid XHTTP xmux range")
			}
		}
		if (m.MaxConcurrency != (XHTTPRange{}) && m.MaxConnections != (XHTTPRange{})) || m.HKeepAlivePeriod < 0 || m.HKeepAlivePeriod > 86400 || alpn == "h3" {
			return fmt.Errorf("unsupported XHTTP xmux settings")
		}
	}
	if d := o.DownloadSettings; d != nil {
		if mode == "stream-one" || (mode == "auto" && security == "reality") || d.Address == "" || d.Port < 1 || d.Port > 65535 || d.Network != "xhttp" || (d.Security != "tls" && d.Security != "reality") {
			return fmt.Errorf("invalid XHTTP download settings")
		}
		if strings.ContainsAny(d.Address, " /\\@?#\t\r\n") || strings.ContainsAny(d.ServerName, " /\\@?#\t\r\n") || strings.ContainsAny(d.Host, "\r\n") || strings.ContainsAny(d.Path, "\r\n") {
			return fmt.Errorf("invalid XHTTP download endpoint")
		}
		if d.Security == "reality" {
			if d.ServerName == "" || d.Fingerprint == "" || d.PublicKey == "" || d.ALPN == "h3" {
				return fmt.Errorf("invalid XHTTP download REALITY settings")
			}
			key, err := base64.RawURLEncoding.DecodeString(d.PublicKey)
			if err != nil || len(key) != 32 || len(d.ShortID) > 16 || len(d.ShortID)%2 != 0 {
				return fmt.Errorf("invalid XHTTP download REALITY key")
			}
			if _, err := hex.DecodeString(d.ShortID); err != nil {
				return fmt.Errorf("invalid XHTTP download REALITY short ID")
			}
			switch d.Fingerprint {
			case "chrome", "firefox", "safari", "ios", "android", "edge":
			default:
				return fmt.Errorf("unsupported XHTTP download fingerprint")
			}
		} else if d.PublicKey != "" || d.ShortID != "" {
			return fmt.Errorf("REALITY options require download security=reality")
		}
		if d.ALPN != "" && d.ALPN != "h2" && d.ALPN != "h3" || d.ALPN == "h3" && d.Fingerprint != "" {
			return fmt.Errorf("invalid XHTTP download ALPN")
		}
		if d.Fingerprint != "" {
			switch d.Fingerprint {
			case "chrome", "firefox", "safari", "ios", "android", "edge":
			default:
				return fmt.Errorf("unsupported XHTTP download fingerprint")
			}
		}
		if d.Host != "" {
			host, err := url.Parse("https://" + d.Host)
			if err != nil || host.Hostname() == "" || host.User != nil || host.Path != "" || host.RawQuery != "" || host.Fragment != "" || strings.ContainsAny(d.Host, " /\\@?#\t\r\n") {
				return fmt.Errorf("invalid XHTTP download host")
			}
		}
		if d.Path != "" && (!strings.HasPrefix(d.Path, "/") || strings.ContainsAny(d.Path, "#\\")) {
			return fmt.Errorf("invalid XHTTP download path")
		}
	}
	return nil
}

// SetXHTTPConfField maps simple .conf fields to the same model as link extra.
func (o *XHTTPOptions) SetXHTTPConfField(key, value string) error {
	field := strings.TrimPrefix(key, "XHTTP")
	if field == "" {
		return fmt.Errorf("unknown XHTTP option")
	}
	name := strings.ToLower(field[:1]) + field[1:]
	target := reflect.ValueOf(o).Elem().FieldByName(field)
	if !target.IsValid() || !target.CanSet() {
		return fmt.Errorf("unknown XHTTP option")
	}
	var raw json.RawMessage
	switch {
	case target.Kind() == reflect.Bool:
		if value != "true" && value != "false" {
			return fmt.Errorf("invalid XHTTP boolean")
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
		return err
	}
	target.Set(reflect.ValueOf(parsed).Elem().FieldByName(field))
	return nil
}
