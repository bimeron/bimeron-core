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
	for path, want := range map[string]string{
		dir:                               "could not read MASQUE CA file",
		filepath.Join(dir, "missing.pem"): "could not read MASQUE CA file",
		large:                             "MASQUE CA file exceeds the 1 MiB size limit",
	} {
		if c, err := New(masqueWithCA(t, path), net.Dialer{}); err == nil || err.Error() != want {
			if c != nil {
				c.Close()
			}
			t.Errorf("CAFile %q: error = %v", path, err)
		}
	}
}
