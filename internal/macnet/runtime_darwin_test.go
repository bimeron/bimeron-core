//go:build darwin

package macnet

import (
	"context"
	"errors"
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

func TestRunCommandCancellationAndFailure(t *testing.T) {
	// A harmless executable exercises exec error handling without network tools.
	tools["test-command"] = "/usr/bin/false"
	defer delete(tools, "test-command")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runCommand(ctx, "test-command", ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := runCommand(context.Background(), "test-command", ""); err == nil || errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
