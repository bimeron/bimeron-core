package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigFlagsRejectAmbiguousOverrides(t *testing.T) {
	for _, args := range [][]string{{"-config", "file.conf", "test.key"}, {"-config", "file.conf", "-dns", "8.8.8.8"}} {
		flags := flag.NewFlagSet("test", flag.ContinueOnError)
		path := flags.String("config", "", "")
		flags.String("dns", "1.1.1.1", "")
		if err := flags.Parse(args); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(flags, *path, "connect"); err == nil {
			t.Fatal("ambiguous config flags accepted")
		}
	}
}
func TestModeIsCheckedBeforeNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.conf")
	if err := os.WriteFile(path, []byte("[Profile]\nVersion = 1\n[AccessKey]\nKey = ss://aes-256-gcm:secret@example.com:8388\n[Interface]\nMode = proxy\n"), 0600); err != nil {
		t.Fatal(err)
	}
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	value := flags.String("config", "", "")
	_ = flags.Parse([]string{"-config", path})
	if _, err := loadConfig(flags, *value, "connect"); err == nil {
		t.Fatal("proxy profile accepted as system VPN")
	}
}
