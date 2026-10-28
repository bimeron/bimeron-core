package config

import (
	"context"
	"strings"
	"testing"
)

const ikev2Config = `[Profile]
Version = 1
Name = Corporate VPN
[IKEv2]
WindowsProfile = Corporate VPN
ServerName = vpn.example.com
`

func TestIKEv2ConfigurationAndNoPacketDefaults(t *testing.T) {
	c, err := ParseData([]byte(ikev2Config))
	if err != nil {
		t.Fatal(err)
	}
	if c.IKEv2 == nil || c.IKEv2.WindowsProfile != "Corporate VPN" || c.Tunnel.Mode != "vpn" || c.Tunnel.DNS != "" || c.Tunnel.MTU != 0 || c.Tunnel.IPv6 != "system" {
		t.Fatal(c)
	}
	if _, err := c.Resolve(context.Background()); err == nil {
		t.Fatal("system profile treated as proxy upstream")
	}
	if _, err := c.ResolveWithTransport(context.Background(), nil); err == nil {
		t.Fatal("system profile treated as remote key")
	}
}

func TestIKEv2RejectsUnsupportedSettingsBeforeStart(t *testing.T) {
	for _, extra := range []string{
		"[AccessKey]\nSS = ss://aes-256-gcm:secret@example.com:8388\n",
		"[AccessKey]\nIdentityFile = private-key\n",
		"[Interface]\nMode = proxy\n",
		"[Interface]\nDNS = 1.1.1.1\n",
		"[Interface]\nMTU = 1400\n",
		"[Interface]\nIPv6 = disable\n",
		"[Interface]\nKillSwitch = true\n",
		"[Interface]\nListen = 127.0.0.1:1080\n",
		"[Interface]\nName = Bimeron\n",
		"[Routing]\nDefault = direct\n",
		"[Rule]\nCIDR = 10.0.0.0/8\nAction = direct\n",
		"[Rule]\nDomain = example.com\nAction = block\n",
	} {
		t.Run(strings.ReplaceAll(extra, "\n", " "), func(t *testing.T) {
			if _, err := ParseData([]byte(ikev2Config + extra)); err == nil {
				t.Fatal("silently ignored unsupported settings")
			}
		})
	}
	for _, data := range []string{
		strings.Replace(ikev2Config, "ServerName = vpn.example.com\n", "", 1),
		strings.Replace(ikev2Config, "WindowsProfile = Corporate VPN\n", "", 1),
		ikev2Config + "Password = never-accept-this\n",
		ikev2Config + "[IKEv2]\nServerName = other.example.com\n",
	} {
		if _, err := ParseData([]byte(data)); err == nil {
			t.Fatal("accepted incomplete/ambiguous configuration")
		}
	}
}

func TestIKEv2NativeProtectionIsExplicit(t *testing.T) {
	for _, value := range []string{"true", "false"} {
		c, err := ParseData([]byte(ikev2Config + "KillSwitch = " + value + "\n"))
		if err != nil || c.IKEv2.KillSwitch != (value == "true") || c.Tunnel.KillSwitch {
			t.Fatal(c, err)
		}
	}
	if _, err := ParseData([]byte(ikev2Config + "KillSwitch = yes\n")); err == nil {
		t.Fatal("ambiguous protection setting accepted")
	}
}
