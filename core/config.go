package core

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"bimeron/internal/accesskey"
	"bimeron/internal/config"
	"bimeron/internal/dnsconfig"
	"bimeron/internal/routing"
	"bimeron/internal/sshtunnel"
	"bimeron/internal/telemetry"
)

type Profile = accesskey.Profile
type Endpoint = accesskey.Endpoint
type Policy = routing.Policy

// SessionConfig is copied by Start. Resolve must honor cancellation and must not
// modify shared state. It is called again after every reconnect (refreshing ssconf).
type SessionConfig struct {
	ProfileID, ProfileName string
	Mode, Name, Listen     string
	MTU                    int
	DNS                    []string
	DisableIPv6            bool
	KillSwitch             bool
	Policy                 *Policy
	Resolve                func(context.Context) (Profile, error)
	// ResolveOnNetwork is used by the VPN control plane while tunnel routes remain
	// installed. Custom key providers should use this transport for their requests.
	ResolveOnNetwork func(context.Context, http.RoundTripper) (Profile, error)
	SSHPrompt        sshtunnel.Prompt
	SSHDefaultKeys   bool

	// stats is injected by Engine.Start and shared by every handler generation.
	stats *telemetry.Counters
	// endpointChanged publishes only transport addresses to local session status.
	endpointChanged func(sessionEndpoints)
}

func DefaultConfig() SessionConfig {
	return SessionConfig{Mode: "vpn", Name: "Bimeron", Listen: "127.0.0.1:1080", MTU: 1420, DNS: []string{"1.1.1.1"}, SSHDefaultKeys: true}
}

func LoadConfig(path string) (SessionConfig, error) {
	c, err := config.Load(path)
	if err != nil {
		return SessionConfig{}, err
	}
	session, err := FromConfig(c)
	if err != nil {
		return SessionConfig{}, err
	}
	session.ProfileID, err = ProfileIdentity(path)
	return session, err
}

// LoadConfigData is for sandboxed hosts. It never accesses configuration/key
// files; supply SS, SSConf, SOCKS5, VLESS, VMess, Trojan, Key or explicit server parameters in the contents.
func LoadConfigData(data []byte) (SessionConfig, error) {
	c, err := config.ParseData(data)
	if err != nil {
		return SessionConfig{}, err
	}
	return FromConfig(c)
}

// ProfileIdentity identifies a path without publishing it or the key contents.
func ProfileIdentity(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	if runtime.GOOS == "windows" {
		absolute = strings.ToLower(absolute)
	}
	digest := sha256.Sum256([]byte(absolute))
	return fmt.Sprintf("%x", digest), nil
}

func FromConfig(c *config.File) (SessionConfig, error) {
	if c == nil {
		return SessionConfig{}, fmt.Errorf("missing configuration")
	}
	// Capture values and the resolved key source, so subsequent caller mutations
	// of the configuration cannot change a running session.
	copy := *c
	p, err := routing.Compile(copy.Routing)
	if err != nil {
		return SessionConfig{}, err
	}
	dns, err := dnsconfig.Parse(copy.Tunnel.DNS)
	if err != nil {
		return SessionConfig{}, err
	}
	if copy.Tunnel.Mode == "vpn" {
		p, err = copy.VPNPolicy()
	}
	if err != nil {
		return SessionConfig{}, err
	}
	return SessionConfig{ProfileName: copy.Name, Mode: copy.Tunnel.Mode, Name: copy.Tunnel.Name, Listen: copy.Tunnel.Listen, MTU: copy.Tunnel.MTU,
		DNS: dns, DisableIPv6: copy.Tunnel.IPv6 == "disable", KillSwitch: copy.Tunnel.KillSwitch, Policy: p, Resolve: copy.Resolve, ResolveOnNetwork: copy.ResolveWithTransport, SSHDefaultKeys: true}, nil
}

// KeyFile retains the legacy command syntax. The file is reread on reconnect.
func KeyFile(path string) SessionConfig {
	c := DefaultConfig()
	c.Resolve = func(ctx context.Context) (Profile, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return Profile{}, fmt.Errorf("could not read key file")
		}
		return accesskey.NewResolver().Resolve(ctx, string(b))
	}
	c.ResolveOnNetwork = func(ctx context.Context, t http.RoundTripper) (Profile, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return Profile{}, fmt.Errorf("could not read key file")
		}
		return accesskey.NewResolverWithTransport(t).Resolve(ctx, string(b))
	}
	return c
}

func (c SessionConfig) validate() error {
	if c.Resolve == nil {
		return fmt.Errorf("missing access key resolver")
	}
	if c.Mode != "vpn" && c.Mode != "proxy" {
		return fmt.Errorf("mode must be vpn or proxy")
	}
	if c.Mode == "proxy" {
		if c.KillSwitch {
			return fmt.Errorf("KillSwitch requires VPN mode")
		}
		a, e := netip.ParseAddrPort(c.Listen)
		if e != nil || !a.Addr().IsLoopback() || a.Port() == 0 {
			return fmt.Errorf("SOCKS listener must use loopback")
		}
		if c.DisableIPv6 {
			return fmt.Errorf("IPv6 disable requires VPN mode")
		}
		return nil
	}
	if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`).MatchString(c.Name) {
		return fmt.Errorf("invalid tunnel name")
	}
	if c.MTU < 1280 || c.MTU > 1500 {
		return fmt.Errorf("MTU must be between 1280 and 1500")
	}
	_, err := dnsconfig.Parse(strings.Join(c.DNS, ","))
	return err
}
