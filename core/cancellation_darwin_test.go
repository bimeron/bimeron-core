//go:build darwin

package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bimeron/internal/macnet"
)

func TestMacOSStopDuringNetworkSetup(t *testing.T) {
	for _, stage := range []string{"inspect", "configure", "retry"} {
		for _, outcome := range []string{"cancel", "command_failure", "cleanup_failure"} {
			if stage == "inspect" && outcome == "cleanup_failure" {
				continue
			}
			t.Run(stage+"/"+outcome, func(t *testing.T) {
				entered := make(chan struct{})
				cleaned := false
				var setupCtx context.Context
				m := &macnet.Manager{Dir: t.TempDir(), Index: func(string) (int, error) { return 12, nil }}
				m.Run = func(ctx context.Context, name, input string, args ...string) ([]byte, error) {
					if name == "networksetup" {
						close(entered)
						if outcome == "command_failure" {
							return nil, errors.New("networksetup command failed")
						}
						<-ctx.Done()
						return nil, context.Canceled
					}
					if name == "netstat" {
						if ctx.Err() != nil {
							t.Error("cleanup used cancelled context")
						}
						if _, err := os.Stat(filepath.Join(m.Dir, "state.json")); err == nil && ctx != setupCtx {
							cleaned = true
							if outcome == "cleanup_failure" {
								return nil, errors.New("cleanup inspection failed")
							}
						}
						return []byte("Destination Gateway Flags Netif Expire\n"), nil
					}
					if name == "route" && strings.Join(args, " ") == "-n get -inet default" {
						return []byte("gateway: 192.0.2.1\ninterface: en0\n"), nil
					}
					return nil, nil
				}
				attempt := 0
				e := testEngine(fakeBackend{open: func(ctx context.Context) (session, error) {
					setupCtx = ctx
					attempt++
					if stage == "retry" && attempt == 1 {
						return nil, fault("network_unavailable", true)
					}
					var err error
					if stage == "inspect" {
						_, err = (&darwinPlatform{manager: m}).Inspect(ctx, "", true)
					} else {
						err = m.Configure(ctx, "utun3", 1420)
					}
					return nil, macosFault(err, "macos_network_setup_failed", false)
				}})
				ctx := testDeadline(t)
				defer e.Stop(context.Background())
				if err := e.Start(ctx, testConfig()); err != nil {
					t.Fatal(err)
				}
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("setup not reached")
				}
				var err error
				if outcome == "command_failure" {
					err = e.Wait(ctx)
				} else {
					err = e.Stop(ctx)
				}
				if outcome == "cancel" {
					if err != nil || e.Status().State != Disconnected {
						t.Fatal(err, e.Status())
					}
				} else {
					if err == nil || e.Status().State != Failed {
						t.Fatal(err, e.Status())
					}
					if outcome == "cleanup_failure" && err.Error() != "cleanup_failed_run_recover" {
						t.Fatal(err)
					}
				}
				if stage != "inspect" {
					if !cleaned {
						t.Fatal("rollback was not invoked")
					}
					state, loadErr := m.Load()
					if loadErr != nil {
						t.Fatal(loadErr)
					}
					if (state != nil) != (outcome == "cleanup_failure") {
						t.Fatal("unexpected recovery journal", state)
					}
				}
			})
		}
	}
}
