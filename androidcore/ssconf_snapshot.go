package androidcore

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"bimeron/core"
	"bimeron/internal/accesskey"
	"bimeron/internal/config"
)

// SSConfSnapshot is an immutable, locally validated SSConf body. It proves
// validation, not authenticity. The host owns source/revision/digest/attempt/lease
// pairing and persistence; reload with the exact persisted source and body.
type SSConfSnapshot struct {
	source  string
	content []byte
	profile accesskey.Profile
}

// NewSSConfSnapshot copies and parses 1..65536 bytes without files or networking.
// Identity is exactly strings.TrimSpace(source), including the fragment. Refresh
// requires a new snapshot. Content is an ss URI or strict Shadowsocks YAML/JSON.
func NewSSConfSnapshot(source string, content []byte) (*SSConfSnapshot, error) {
	source = strings.TrimSpace(source)
	invalid := errors.New("invalid SSConf snapshot source")
	if !strings.HasPrefix(source, "ssconf://") {
		return nil, invalid
	}
	u, err := url.Parse("https://" + strings.TrimPrefix(source, "ssconf://"))
	if err != nil || u.Hostname() == "" || u.User != nil {
		return nil, invalid
	}
	if u.Port() != "" {
		addr, err := netip.ParseAddrPort(net.JoinHostPort("127.0.0.1", u.Port()))
		if err != nil || addr.Port() == 0 {
			return nil, invalid
		}
	}
	if len(content) == 0 || len(content) > 65536 {
		return nil, errors.New("invalid SSConf snapshot content")
	}
	body := append([]byte(nil), content...)
	p, err := accesskey.ParseConfig(body)
	if err != nil {
		return nil, errors.New("invalid SSConf snapshot content")
	}
	if u.Fragment != "" {
		p.Name = u.Fragment
	}
	return &SSConfSnapshot{source: source, content: body, profile: p}, nil
}

// NewSessionWithSSConfSnapshot validates a full sandbox configuration and pins
// both resolver paths to snapshot. Construction starts no networking or callbacks.
// The host must call SetNetwork and Start. Reconnect never refreshes the snapshot.
func NewSessionWithSSConfSnapshot(profile []byte, snapshot *SSConfSnapshot, geoIP, geoSite []byte, protector SocketProtector) (*Session, error) {
	if snapshot == nil || snapshot.source == "" || len(snapshot.content) == 0 {
		return nil, errors.New("SSConf snapshot required")
	}
	if protector == nil {
		return nil, errors.New("socket protector required")
	}
	c, err := config.ParseDataWithGeoData(append([]byte(nil), profile...), append([]byte(nil), geoIP...), append([]byte(nil), geoSite...))
	if err != nil {
		return nil, errors.New("invalid SSConf session configuration")
	}
	if err := c.InstallSSConfSnapshot(snapshot.source, snapshot.profile); err != nil {
		return nil, errors.New("invalid SSConf snapshot binding")
	}
	cfg, err := core.FromConfig(c)
	if err != nil {
		return nil, errors.New("invalid SSConf session configuration")
	}
	s, err := newSession(cfg, protector)
	if err != nil {
		return nil, errors.New("invalid SSConf session configuration")
	}
	return s, nil
}
