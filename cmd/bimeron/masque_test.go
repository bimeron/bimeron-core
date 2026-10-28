package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckMASQUEInitializesVerifiedTransport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "masque.conf")
	text := "[Profile]\nVersion = 1\n[AccessKey]\nType = masque\nServer = 127.0.0.1\nPort = 443\nCAFile = missing.pem\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if err := check([]string{"-config", path}); err == nil || err.Error() != "could not read MASQUE CA file" {
		t.Fatalf("check initialized wrong transport: %v", err)
	}
}
