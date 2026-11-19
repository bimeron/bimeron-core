package config

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const trustHead = "[Profile]\nVersion = 1\n\n[AccessKey]\n"

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
	for _, tc := range []struct {
		name, access string
		want         []TrustFile
	}{
		{"no files", "SSH = ssh://alice@example.com", []TrustFile{}},
		{"shadowsocks", "SS = ss://aes-256-gcm:secret@example.com:8388", []TrustFile{}},
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
			got := loadFile(t, dir, trustHead+tc.access+"\n").TrustFiles()
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("TrustFiles() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestTrustFilesKeepHomeRelativePaths(t *testing.T) {
	c := loadFile(t, t.TempDir(), trustHead+"SSH = ssh://alice@example.com?known_hosts=~/.ssh/known_hosts\n")
	want := []TrustFile{{TrustSSHKnownHosts, TrustFromURI, "~/.ssh/known_hosts"}}
	if got := c.TrustFiles(); !reflect.DeepEqual(got, want) {
		t.Fatalf("TrustFiles() = %+v, want %+v", got, want)
	}
}

// TestTrustFilesMatchOpenedPaths checks that the session opens exactly the
// reported paths.
func TestTrustFilesMatchOpenedPaths(t *testing.T) {
	dir := t.TempDir()
	for _, access := range []string{
		"SSH = ssh://alice@example.com?identity=./keys/../id&known_hosts=a//kh",
		"Type = ssh\nServer = example.com\nPort = 22\nUsername = alice\nIdentityFile = x/../id\nKnownHostsFile = ./kh",
		"Type = masque\nServer = proxy.example\nPort = 443\nCAFile = ./ca/../ca.pem",
	} {
		c := loadFile(t, dir, trustHead+access+"\n")
		p, err := c.Resolve(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		opened := map[string]string{TrustSSHIdentity: p.SSH.IdentityFile, TrustSSHKnownHosts: p.SSH.KnownHostsFile, TrustMASQUECA: p.MASQUE.CAFile}
		files := c.TrustFiles()
		if len(files) == 0 {
			t.Fatalf("%q: no trust files", access)
		}
		for _, f := range files {
			if f.Path != opened[f.Kind] || !filepath.IsAbs(f.Path) || f.Path != filepath.Clean(f.Path) {
				t.Errorf("%q: %s reported %q, opened %q", access, f.Kind, f.Path, opened[f.Kind])
			}
		}
	}
}
