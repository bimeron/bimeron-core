package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestCheckHTTPSProxyRejectsUntrustedCertificate(t *testing.T) {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("check sent CONNECT before TLS verification")
	}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	defer s.Close()
	path := filepath.Join(t.TempDir(), "https.conf")
	text := "[Profile]\nVersion = 1\n[AccessKey]\nHTTP = " + strings.Replace(s.URL, "https://", "https://alice:secret@", 1) + "\n[Interface]\nMode = proxy\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	err := check([]string{"-config", path})
	if err == nil || !strings.Contains(err.Error(), "HTTPS proxy TLS failed") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("check did not enforce proxy TLS: %v", err)
	}
}
