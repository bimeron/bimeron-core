package config

import (
	"bimeron/internal/routing"
	"context"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSS2022ExplicitIdentityChain(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	chain := key + ":" + key + ":" + key
	c, err := loadText(t, "[Profile]\nVersion = 1\n[AccessKey]\nType = shadowsocks\nServer = example.com\nPort = 8388\nMethod = 2022-blake3-aes-128-gcm\nPassword = "+chain+"\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Resolve(context.Background())
	if err != nil || p.TCP.Secret != chain || p.UDP.Secret != chain {
		t.Fatalf("explicit chain: %v", err)
	}
}

func loadText(t *testing.T, text string) (*File, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profile.conf")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

const staticConfig = `[Profile]
Version = 1
[AccessKey]
Key = ss://aes-256-gcm:secret@example.com:8388
`

func TestKillSwitchConfig(t *testing.T) {
	for _, value := range []string{"true", "false"} {
		c, err := loadText(t, staticConfig+"[Interface]\nKillSwitch = "+value+"\n")
		if err != nil || c.Tunnel.KillSwitch != (value == "true") {
			t.Fatal(value, err)
		}
	}
	for _, extra := range []string{"KillSwitch = yes\n", "KillSwitch = true\nMode = proxy\n"} {
		if _, err := loadText(t, staticConfig+"[Interface]\n"+extra); err == nil {
			t.Fatal("invalid kill switch config accepted")
		}
	}
}

func TestRepeatedRulesAndFirstMatch(t *testing.T) {
	c, err := loadText(t, staticConfig+`[Routing]
Default = direct
[Rule]
CIDR = 203.0.113.5/32
Action = block
[Rule]
CIDR = 203.0.113.0/24
Action = proxy
`)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.VPNPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if p.Decide(netip.MustParseAddr("203.0.113.5"), "") != routing.Block || p.Decide(netip.MustParseAddr("203.0.113.6"), "") != routing.Proxy {
		t.Fatal("rule ordering lost")
	}
	if c.Tunnel.MTU != 1420 || c.Tunnel.DNS != "1.1.1.1" {
		t.Fatal("missing defaults")
	}
}
func TestRelativeKeyFileIndependentOfWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.key"), []byte("\ufeffss://aes-256-gcm:secret@example.com:8388"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "main.conf")
	if err := os.WriteFile(path, []byte("[Profile]\nVersion = 1\n[AccessKey]\nFile = test.key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Resolve(context.Background())
	if err != nil || p.TCP.Secret != "secret" {
		t.Fatalf("relative path: %v", err)
	}
}
func TestDynamicFragmentsAndQueriesPreservedWithoutFetch(t *testing.T) {
	key := "ssconf://example.invalid/config?token=a=b#display-name"
	c, err := loadText(t, "[Profile]\nVersion = 1\n[AccessKey]\nKey = "+key+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.key != key {
		t.Fatal("URL fragment or query lost")
	}
}
func TestStructuredCredentialsAndQuotedPrefix(t *testing.T) {
	c, err := loadText(t, `[Profile]
Version = 1
[AccessKey]
Type = shadowsocks
Server = example.com
Port = 8388
Method = aes-256-gcm
Password = " secret=with#fragment; "
Prefix = "GET \r\n"
`)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.TCP.Secret != " secret=with#fragment; " || p.TCP.Prefix != "GET \r\n" {
		t.Fatal("credentials corrupted")
	}
}
func TestRejectedConfigDoesNotLeakSecrets(t *testing.T) {
	bad := []string{
		strings.Replace(staticConfig, "Version = 1", "Version = 2", 1),
		staticConfig + "[AccessKey]\nFile = test.key\n",
		staticConfig + "Key = TOP-SECRET\n",
		staticConfig + "Unknown = TOP-SECRET\n",
		staticConfig + "File = TOP-SECRET\n",
		staticConfig + "[Interface]\nMTU = 900\n",
		staticConfig + "[Interface]\nListen = 0.0.0.0:1080\n",
		staticConfig + "[Interface]\nDNS = TOP-SECRET\n",
		staticConfig + "[Rule]\nCIDR = 203.0.113.0/24\n",
		staticConfig + "[Unknown]\nValue = TOP-SECRET\n",
		staticConfig + "[Interface]\nMode = proxy\nMode = vpn\n",
		staticConfig + strings.Repeat("#x\n", maxSize),
	}
	for i, s := range bad {
		_, err := loadText(t, s)
		if err == nil {
			t.Fatalf("invalid config %d accepted", i)
		}
		if strings.Contains(err.Error(), "TOP-SECRET") {
			t.Fatal("secret leaked in error")
		}
	}
}
func TestProxyDomainRules(t *testing.T) {
	_, err := loadText(t, staticConfig+"[Interface]\nMode = proxy\nListen = 127.0.0.1:11080\n[Rule]\nDomain = example.com\nAction = direct\n")
	if err != nil {
		t.Fatal(err)
	}
}
func TestVPNDomainRules(t *testing.T) {
	c, err := loadText(t, staticConfig+"[Rule]\nDomain = example.com\nAction = direct\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.VPNPolicy()
	if err != nil || p.Decide(netip.MustParseAddr("203.0.113.1"), "www.example.com") != routing.Direct {
		t.Fatal("VPN domain rule unavailable", err)
	}
}
func TestUTF8BOM(t *testing.T) {
	if _, err := loadText(t, "\ufeff"+staticConfig); err != nil {
		t.Fatal(err)
	}
}

func TestExplicitSSAndSSConf(t *testing.T) {
	c, err := loadText(t, "[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://aes-256-gcm:secret@example.com:8388#demo\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Resolve(context.Background())
	if err != nil || p.TCP.Secret != "secret" || p.Name != "demo" {
		t.Fatalf("SS: %v", err)
	}
	key := "ssconf://example.invalid/config?token=a=b#demo"
	c, err = loadText(t, "[Profile]\nVersion = 1\n[AccessKey]\nSSConf = "+key+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.key != key {
		t.Fatal("SSConf URL altered")
	}
}
func TestAllKeySourcesAreMutuallyExclusive(t *testing.T) {
	sources := []string{"File = test.key", "SS = ss://aes-256-gcm:secret@example.com:8388", "SSConf = ssconf://example.invalid/config", "SOCKS5 = socks5://example.com:1080", "Key = ss://aes-256-gcm:secret@example.com:8388", "Type = shadowsocks\nServer = example.com\nPort = 8388\nMethod = aes-256-gcm\nPassword = secret"}
	for i := range sources {
		for j := i + 1; j < len(sources); j++ {
			_, err := loadText(t, "[Profile]\nVersion = 1\n[AccessKey]\n"+sources[i]+"\n"+sources[j]+"\n")
			if err == nil || !strings.Contains(err.Error(), "exactly one source") {
				t.Fatalf("sources %d and %d not rejected before key-file access: %v", i, j, err)
			}
		}
	}
}
func TestExplicitSchemeValidation(t *testing.T) {
	for _, option := range []string{"SS = ssconf://example.invalid/secret", "SSConf = ss://aes-256-gcm:secret@example.com:8388", "SS = secret", "SSConf = secret", "SS = "} {
		if _, err := loadText(t, "[Profile]\nVersion = 1\n[AccessKey]\n"+option+"\n"); err == nil {
			t.Fatal("wrong access key scheme accepted")
		}
	}
}

func TestSOCKS5SourcesAndRequiredType(t *testing.T) {
	base := "[Profile]\nVersion = 1\n[AccessKey]\n"
	for _, source := range []string{
		"Key = socks5://alice:secret@proxy.example.com:1080",
		"SOCKS5 = socks5://alice:secret@proxy.example.com:1080",
		"Type = socks5\nServer = proxy.example.com\nPort = 1080\nUsername = alice\nPassword = secret",
	} {
		c, err := loadText(t, base+source+"\n")
		if err != nil {
			t.Fatal(err)
		}
		p, err := c.Resolve(context.Background())
		if err != nil || p.Type != "socks5" || p.Username != "alice" || p.TCP.Secret != "secret" {
			t.Fatalf("%s: %+v %v", source, p, err)
		}
	}
	noAuth, err := loadText(t, base+"Type = socks5\nServer = proxy.example.com\nPort = 1080\n")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := noAuth.Resolve(context.Background())
	if err != nil || profile.Type != "socks5" || profile.Username != "" {
		t.Fatal("no-auth SOCKS5 profile", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "proxy.key"), []byte("socks5://proxy.example.com:1080"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "profile.conf")
	if err := os.WriteFile(path, []byte(base+"File = proxy.key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	profile, err = fromFile.Resolve(context.Background())
	if err != nil || profile.Type != "socks5" {
		t.Fatal("SOCKS5 File source", err)
	}
	for _, kind := range []string{"shadowsocks", "ss"} {
		c, err := loadText(t, base+"Type = "+kind+"\nServer = example.com\nPort = 8388\nMethod = aes-256-gcm\nPassword = secret\n")
		if err != nil {
			t.Fatal(err)
		}
		p, err := c.Resolve(context.Background())
		if err != nil || p.TCP.Cipher != "aes-256-gcm" {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	for _, source := range []string{
		"Server = example.com\nPort = 8388\nMethod = aes-256-gcm\nPassword = secret",
		"Type = socks5\nServer = example.com\nPort = 1080\nUsername = alice",
		"Type = socks5\nServer = example.com\nPort = 1080\nMethod = aes-256-gcm",
		"Type = shadowsocks\nServer = example.com\nPort = 8388\nMethod = aes-256-gcm\nPassword = secret\nUsername = alice",
		"SOCKS5 = ss://example.com",
	} {
		if _, err := loadText(t, base+source+"\n"); err == nil {
			t.Fatalf("invalid source accepted: %s", source)
		}
	}
}

func TestMultipleDNSConfig(t *testing.T) {
	c, err := loadText(t, staticConfig+"[Interface]\nDNS = 1.1.1.1, 8.8.8.8\n")
	if err != nil || c.Tunnel.DNS != "1.1.1.1, 8.8.8.8" {
		t.Fatalf("DNS config: %v", err)
	}
	for _, value := range []string{"1.1.1.1,", "1.1.1.1,1.1.1.1", "1.1.1.1,::1"} {
		if _, err := loadText(t, staticConfig+"[Interface]\nDNS = "+value+"\n"); err == nil {
			t.Fatal("invalid DNS config accepted")
		}
	}
}

func TestCIDRList(t *testing.T) {
	c, err := loadText(t, staticConfig+`[Routing]
Default = direct
[Rule]
CIDR = 8.8.8.8/32
Action = block
[Rule]
CIDR = 8.8.4.0/24, 8.8.8.0/24, 8.34.208.0/20, 2001:db8::/32
Action = proxy
[Rule]
CIDR = 8.8.4.4/32
Action = direct
`)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.VPNPolicy()
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]routing.Action{
		"8.8.8.8": routing.Block, "8.8.8.9": routing.Proxy,
		"8.8.4.4": routing.Proxy, "8.34.223.255": routing.Proxy,
		"8.34.224.0": routing.Direct, "2001:db8::1": routing.Proxy,
		"1.1.1.1": routing.Direct,
	} {
		if got := p.Decide(netip.MustParseAddr(ip), ""); got != want {
			t.Fatalf("%s: got %s, want %s", ip, got, want)
		}
	}
	for _, value := range []string{"8.8.8.0/24,", ",8.8.8.0/24", "8.8.8.0/24,,8.8.4.0/24", "8.8.8.0/24, bad", "8.8.8.0/24, 1.1.1.1", "8.8.8.0/24, 2001:db8::/129"} {
		if _, err := loadText(t, staticConfig+"[Rule]\nCIDR = "+value+"\nAction = proxy\n"); err == nil {
			t.Fatalf("accepted invalid CIDR list %q", value)
		}
	}
}

func TestIPv6Mode(t *testing.T) {
	for _, mode := range []string{"enable", "disable"} {
		c, err := loadText(t, staticConfig+"[Interface]\nIPv6 = "+mode+"\n")
		if err != nil || c.Tunnel.IPv6 != mode {
			t.Fatalf("mode %s: %v", mode, err)
		}
	}
	for _, extra := range []string{"[Interface]\nIPv6 = bad\n", "[Interface]\nMode = proxy\nIPv6 = disable\n"} {
		if _, err := loadText(t, staticConfig+extra); err == nil {
			t.Fatal("accepted invalid IPv6 configuration")
		}
	}
	c, err := loadText(t, staticConfig)
	if err != nil || c.Tunnel.IPv6 != "enable" {
		t.Fatal("IPv6 default changed")
	}
}
