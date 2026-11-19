package config

import (
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func loadFile(t *testing.T, dir, profile string) *File {
	t.Helper()
	path := filepath.Join(dir, "profile.conf")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTrustFiles(t *testing.T) {
	dir := t.TempDir()
	abs := func(name string) string { return filepath.Join(dir, name) }
	ca := abs("ca.pem")
	key := abs("ssh.key")
	if err := os.WriteFile(key, []byte("ssh://alice@example.com?known_hosts=kh"), 0o600); err != nil {
		t.Fatal(err)
	}
	const head = "[Profile]\nVersion = 1\n\n[AccessKey]\n"
	for _, tc := range []struct {
		name, access string
		want         []TrustFile
	}{
		{"no files", "SSH = ssh://alice@example.com", nil},
		{"shadowsocks", "SS = ss://aes-256-gcm:secret@example.com:8388", nil},
		{"ssh uri", "SSH = ssh://alice@example.com?identity=id&known_hosts=sub/../kh", []TrustFile{
			{TrustSSHIdentity, TrustFromURI, abs("id")},
			{TrustSSHKnownHosts, TrustFromURI, abs("kh")},
		}},
		{"ssh key option", "Key = ssh://alice@example.com?known_hosts=kh", []TrustFile{{TrustSSHKnownHosts, TrustFromURI, abs("kh")}}},
		{"ssh key file", "File = ssh.key", []TrustFile{{TrustSSHKnownHosts, TrustFromURI, abs("kh")}}},
		{"ssh option overrides uri", "SSH = ssh://alice@example.com?known_hosts=kh&identity=id\nKnownHostsFile = own_kh", []TrustFile{
			{TrustSSHIdentity, TrustFromURI, abs("id")},
			{TrustSSHKnownHosts, TrustFromOption, abs("own_kh")},
		}},
		{"ssh explicit", "Type = ssh\nServer = example.com\nPort = 22\nUsername = alice\nIdentityFile = ./id", []TrustFile{{TrustSSHIdentity, TrustFromOption, abs("id")}}},
		{"masque uri", "MASQUE = masque://proxy.example?ca=" + url.QueryEscape(ca), []TrustFile{{TrustMASQUECA, TrustFromURI, ca}}},
		{"masque explicit", "Type = masque\nServer = proxy.example\nPort = 443\nCAFile = ca.pem", []TrustFile{{TrustMASQUECA, TrustFromOption, ca}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := loadFile(t, dir, head+tc.access+"\n").TrustFiles()
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("TrustFiles() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestTrustFilesExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("home directory unavailable")
	}
	c := loadFile(t, t.TempDir(), "[Profile]\nVersion = 1\n\n[AccessKey]\nSSH = ssh://alice@example.com?known_hosts=~/.ssh/known_hosts\n")
	want := []TrustFile{{TrustSSHKnownHosts, TrustFromURI, filepath.Join(home, ".ssh", "known_hosts")}}
	if got := c.TrustFiles(); !reflect.DeepEqual(got, want) {
		t.Fatalf("TrustFiles() = %+v, want %+v", got, want)
	}
}
