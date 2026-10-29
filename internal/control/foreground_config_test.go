package control

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestForegroundConfigBindsReviewedNativeBytes(t *testing.T) {
	path, err := filepath.Abs("native.conf")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("[Profile]\nVersion = 1\nName = Native\n[IKEv2]\nWindowsProfile = Corporate VPN\nServerName = vpn.example.com\n")
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	cfg, err := foregroundConfig(path, digest, data)
	if err != nil || cfg.IKEv2 == nil || cfg.ProfileID == "" {
		t.Fatalf("native snapshot rejected: %v", err)
	}
	for _, test := range []struct {
		name, path, digest string
		data               []byte
	}{
		{"changed", path, digest, append(append([]byte(nil), data...), '\n')},
		{"relative", "native.conf", digest, data},
		{"bad_digest", path, strings.Repeat("z", 64), data},
		{"oversized", path, digest, make([]byte, 64*1024+1)},
		{"packet", path, fmt.Sprintf("%x", sha256.Sum256([]byte("[Profile]\nVersion = 1\n[AccessKey]\nKey = socks5://localhost:1080\n"))), []byte("[Profile]\nVersion = 1\n[AccessKey]\nKey = socks5://localhost:1080\n")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := foregroundConfig(test.path, test.digest, test.data); err == nil {
				t.Fatal("unsafe snapshot accepted")
			}
		})
	}
}
