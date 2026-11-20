package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bimeron/internal/problem"
)

func wgKey(b byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b + byte(i)
	}
	return base64.StdEncoding.EncodeToString(k)
}

func explicitWireGuard(extra string) string {
	return "[Profile]\nVersion = 1\n\n[AccessKey]\nType = wireguard\nPrivateKey = " + wgKey(1) + "\nAddress = 10.8.0.2/32\nPublicKey = " + wgKey(2) + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n" + extra
}

func TestExplicitWireGuard(t *testing.T) {
	c, err := ParseData([]byte(explicitWireGuard("Jc = 4\nH1 = 10-20\n")))
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Resolve(t.Context())
	if err != nil || p.Type != "wireguard" || p.WireGuard.AWG["H1"] != "10-20" || p.TCP.Host != "192.0.2.1" || p.UDP.Port != 51820 {
		t.Fatalf("profile %+v %v", p, err)
	}
	cases := map[string]string{
		explicitWireGuard("Jmin = 9\nJmax = 1\n"):                                     "awg_range_invalid",
		explicitWireGuard("Server = x\n"):                                             "option_not_supported",
		explicitWireGuard("ShortID = ab\n"):                                           "option_not_supported",
		strings.Replace(explicitWireGuard(""), "Type = wireguard", "Type = vless", 1): "option_requires_type",
		explicitWireGuard("PostUp = x\n"):                                             "option_unknown",
		explicitWireGuard("[Routing]\nAllowedIPsMode = sometimes\n"):                  "choice_invalid",
		"[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://YWVzLTI1Ni1nY206cGFzcw@192.0.2.1:8388\n[Routing]\nAllowedIPsMode = block\n": "allowed_ips_mode_requires_wireguard",
	}
	for text, want := range cases {
		_, err := ParseData([]byte(text))
		p := problem.Of(err)
		if err == nil || p.Code != want {
			t.Errorf("want %s, got %v", want, err)
			continue
		}
		if p.Document != "" {
			t.Errorf("%s: explicit options must not carry a document marker", want)
		}
	}
	_, err = ParseData([]byte(explicitWireGuard("Jmin = 9\nJmax = 1\n")))
	if p := problem.Of(err); p.Section != "AccessKey" || p.Field != "Jmin" || p.Line != 11 {
		t.Fatalf("location %+v", p)
	}
	c, err = ParseData([]byte(explicitWireGuard("[Routing]\nAllowedIPsMode = only\n")))
	if err != nil || c.AllowedIPsMode != "only" {
		t.Fatal(err)
	}
}

func TestWireGuardFileDNS(t *testing.T) {
	dir := t.TempDir()
	wg := "[Interface]\nPrivateKey = " + wgKey(1) + "\nAddress = 10.8.0.2/32\nDNS = 10.8.0.1, 2001:db8::53, 10.8.0.1\n[Peer]\nPublicKey = " + wgKey(2) + "\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0\n"
	if err := os.WriteFile(filepath.Join(dir, "k.conf"), []byte(wg), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "p.conf")
	for profile, want := range map[string]string{
		"[Profile]\nVersion = 1\n[AccessKey]\nFile = k.conf\n":                             "10.8.0.1",
		"[Profile]\nVersion = 1\n[AccessKey]\nFile = k.conf\n[Interface]\nDNS = 9.9.9.9\n": "10.8.0.1",
	} {
		if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(c.WireGuardDNS(), ","); got != want {
			t.Fatalf("dns %q want %q", got, want)
		}
	}
	if _, err := ParseData([]byte("[Profile]\nVersion = 1\n[AccessKey]\nFile = k.conf\n")); problem.Of(err).Code != "key_file_unavailable" {
		t.Fatal("in-memory File must stay unavailable")
	}
}

func TestWireGuardReviewRegressions(t *testing.T) {
	for _, extra := range []string{"WSEarlyData = 0\n", "GRPCMultiMode = false\n"} {
		_, err := ParseData([]byte(explicitWireGuard(extra)))
		if p := problem.Of(err); err == nil || p.Code != "option_not_supported" {
			t.Errorf("%q: %v", extra, err)
		}
	}
	dir := t.TempDir()
	wg := "[Interface]\nPrivateKey = " + wgKey(1) + "\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = " + wgKey(2) + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n[Routing]\nDefault = proxy\n"
	if err := os.WriteFile(filepath.Join(dir, "k.conf"), []byte(wg), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "p.conf")
	if err := os.WriteFile(path, []byte("[Profile]\nVersion = 1\n[AccessKey]\nFile = k.conf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if p := problem.Of(err); err == nil || p.Code != "document_format_ambiguous" || p.Source != "File" || p.Document != "wireguard" {
		t.Fatalf("ambiguous file: %+v", p)
	}
}

func TestLoadAnyRunsWireGuardFilesDirectly(t *testing.T) {
	dir := t.TempDir()
	wg := "[Interface]\nPrivateKey = " + wgKey(1) + "\nAddress = 10.8.0.2/32\nDNS = 10.8.0.1\nMTU = 1360\nJc = 4\n[Peer]\nPublicKey = " + wgKey(2) + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 10.8.0.0/24\n"
	path := filepath.Join(dir, "My Office.conf")
	if err := os.WriteFile(path, []byte(wg), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadDir(dir)
	c, err := LoadAny(path)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadDir(dir)
	if len(after) != len(before) {
		t.Fatal("direct run wrote a file")
	}
	if !c.IsWireGuard() || c.Name != "My Office" || c.Tunnel.Mode != "vpn" || c.AllowedIPsMode != "only" {
		t.Fatalf("profile %+v", c)
	}
	if protocol, label, _ := c.WireGuardAdapterLabel(); protocol != "AWG" || label != "My Office" {
		t.Fatalf("label %s %s", protocol, label)
	}
	if got := strings.Join(c.WireGuardDNS(), ","); got != "10.8.0.1" || c.WireGuardTunnelMTU() != 1360 {
		t.Fatalf("dns %s mtu %d", got, c.WireGuardTunnelMTU())
	}
	if !IsWireGuardFile(path) {
		t.Fatal("not detected")
	}
	// Bimeron profiles keep loading as before.
	profile := filepath.Join(dir, "p.conf")
	if err := os.WriteFile(profile, []byte("[Profile]\nVersion = 1\n[AccessKey]\nFile = My Office.conf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := LoadAny(profile); err != nil || c.AllowedIPsMode != "" || IsWireGuardFile(profile) {
		t.Fatalf("Bimeron profile: %v", err)
	}
	if err := os.WriteFile(path, []byte(wg+"PostUp = x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAny(path); problem.Of(err).Code != "wireguard_hook_unsupported" || problem.Of(err).Document != "wireguard" {
		t.Fatalf("invalid file: %v", err)
	}
}
