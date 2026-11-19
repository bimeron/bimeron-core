package core

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"bimeron/internal/config"
	"bimeron/internal/wireguard/wgtest"
)

func TestWireGuardAdapterAlias(t *testing.T) {
	cases := map[[2]string]string{
		{"WG", "Office"}:                         "Bimeron WG — Office",
		{"AWG", "Office"}:                        "Bimeron AWG — Office",
		{"WG", "  Дом\tи\nдача \u200b "}:         "Bimeron WG — Дом и дача",
		{"AWG", ""}:                              "Bimeron AWG",
		{"WG", strings.Repeat("x", 100)}:         "Bimeron WG — " + strings.Repeat("x", maxAliasLabel),
		{"WG", "O'Brien \"lab\" (1)"}:            "Bimeron WG — O'Brien \"lab\" (1)",
		{"WG", "a*b?[c]`d"}:                      "Bimeron WG — a_b__c__d",
		{"AWG", "x\u202eevil\u2066"}:             "Bimeron AWG — xevil",
		{"WG", strings.Repeat("\U0001F600", 60)}: "Bimeron WG — " + strings.Repeat("\U0001F600", 43),
	}
	for in, want := range cases {
		got := wireGuardAdapterAlias(in[0], in[1])
		if got != want || !validAdapterAlias(got) {
			t.Errorf("%q: got %q", in, got)
		}
	}
	if validAdapterAlias("Bimeron WG — a\x00b") || validAdapterAlias("Other") {
		t.Fatal("invalid alias accepted")
	}
}

func TestWireGuardSessionAdapterName(t *testing.T) {
	client, server := wgtest.NewKeyPair(t), wgtest.NewKeyPair(t)
	dir := t.TempDir()
	wg := "[Interface]\nPrivateKey = " + wgtest.B64(client.Private) + "\nAddress = 10.8.0.2/32\n%s[Peer]\nPublicKey = " + wgtest.B64(server.Public) + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n"
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("Office.conf", strings.Replace(wg, "%s", "", 1))
	write("Lab.CONF", strings.Replace(wg, "%s", "Jc = 4\nH1 = 10-20\n", 1))
	for _, tc := range []struct{ profile, want string }{
		{"[Profile]\nVersion = 1\nName = Home\n[AccessKey]\nFile = Office.conf\n", "Bimeron WG — Office"},
		{"[Profile]\nVersion = 1\nName = Home\n[AccessKey]\nFile = Lab.CONF\n", "Bimeron AWG — Lab"},
		{"[Profile]\nVersion = 1\nName = Home\n[AccessKey]\nType = wireguard\nPrivateKey = " + wgtest.B64(client.Private) + "\nAddress = 10.8.0.2/32\nPublicKey = " + wgtest.B64(server.Public) + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n", "Bimeron WG — Home"},
	} {
		c, err := config.Load(write("p.conf", tc.profile))
		if err != nil {
			t.Fatal(err)
		}
		s, err := FromConfig(c)
		if err != nil {
			t.Fatal(err)
		}
		want := tc.want
		if runtime.GOOS != "windows" {
			want = "Bimeron" // other platforms keep [Interface] Name
		}
		if s.Name != want {
			t.Fatalf("adapter name %q, want %q", s.Name, want)
		}
	}
}
