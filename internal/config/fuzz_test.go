package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Profiles are untrusted input: parsing must never panic, whatever the bytes.
// The shipped examples seed every section; parsing without a path never reads
// referenced files.
func FuzzParseData(f *testing.F) {
	examples, err := filepath.Glob(filepath.Join("..", "..", "examples", "*.conf"))
	if err != nil || len(examples) == 0 {
		f.Fatal("no example profiles", err)
	}
	for _, name := range examples {
		b, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	header := "[Profile]\nVersion = 1\n"
	for _, seed := range []string{
		header + "[Interface]\nMode = vpn\nKillSwitch = true\n[AccessKey]\nSS = ss://YWVzLTI1Ni1nY206cHc@127.0.0.1:443\n",
		header + "[AccessKey]\nSS = ss://YWVzLTI1Ni1nY206cHc@127.0.0.1:443\n[Routing]\nDefault = proxy\n[Rule]\nCIDR = 10.0.0.0/8\nAction = direct\n[Rule]\nDomain = .example.com\nAction = block\n",
		header + "[AccessKey]\nType = shadowsocks\nServer = \"quoted.example.com\"\nPort = 8388\nMethod = aes-256-gcm\nPassword = \"a;b\"\n",
		"\ufeff" + strings.ReplaceAll(header, "\n", "\r\n") + "[Interface]\r\nMode = vpn\r\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseData(b)
	})
}
