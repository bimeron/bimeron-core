//go:build darwin

package macnet

import (
	"context"
	"os"
	"testing"
	"time"
)

// Opt-in, read-only check against the machine's actual network services.
func TestNativeServiceMapping(t *testing.T) {
	if os.Getenv("BIMERON_MACOS_TEST") != "1" {
		t.Skip("requires opt-in native macOS inspection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	services, err := NewManager().services(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(services) == 0 {
		t.Fatal("no network services matched")
	}
}
