package masque

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"

	"bimeron/internal/accesskey"
)

// masqueWithCA returns a profile whose CAFile is path.
func masqueWithCA(t *testing.T, path string) accesskey.Profile {
	t.Helper()
	p, err := accesskey.ParseMASQUE("masque://proxy.example.com:443?sni=proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}
	p.MASQUE.CAFile = path
	return p
}

func TestNewRequiresRegularBoundedCAFile(t *testing.T) {
	dir := t.TempDir()
	large := filepath.Join(dir, "large.pem")
	if err := os.WriteFile(large, bytes.Repeat([]byte("#"), maxCAFile+1), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, large, filepath.Join(dir, "missing.pem")} {
		if c, err := New(masqueWithCA(t, path), net.Dialer{}); err == nil || err.Error() != "could not read MASQUE CA file" {
			if c != nil {
				c.Close()
			}
			t.Errorf("CAFile %q: error = %v", path, err)
		}
	}
}
