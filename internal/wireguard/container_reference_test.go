//go:build linux

package wireguard

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"bimeron/internal/wgconf"
	"bimeron/internal/wireguard/wgtest"
)

// TestReferenceContainers runs the client against upstream wireguard-go and
// amneziawg-go server processes with kernel TUN devices, one Docker container
// per server. BIMERON_WG_REFERENCE_IMAGE names an image with /refserver
// (internal/wireguard/wgtest/refserver), /wireguard-go and /amneziawg-go;
// docs/WIREGUARD.MD shows how CI builds it. The test process must reach the
// containers' bridge addresses, and the docker CLI must be on PATH.
func TestReferenceContainers(t *testing.T) {
	image := os.Getenv("BIMERON_WG_REFERENCE_IMAGE")
	if image == "" {
		t.Skip("set BIMERON_WG_REFERENCE_IMAGE for containerized reference servers")
	}
	for _, tc := range []struct{ name, server, profile string }{
		{"wireguard-go", "wireguard-go", ""},
		{"amneziawg-go/plain", "amneziawg-go", ""},
		{"amneziawg-go/awg-1.0", "amneziawg-go", "awg-1.0"},
		{"amneziawg-go/awg-1.5", "amneziawg-go", "awg-1.5"},
		{"amneziawg-go/awg-2.0", "amneziawg-go", "awg-2.0"},
		{"amneziawg-go/awg-3.1", "amneziawg-go", "awg-3.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := wgtest.Profiles[tc.profile]
			client := wgtest.NewKeyPair(t)
			s := &wgtest.Server{Key: wgtest.NewKeyPair(t)}
			if _, err := rand.Read(s.PSK[:]); err != nil {
				t.Fatal(err)
			}
			uapi := fmt.Sprintf("private_key=%s\nlisten_port=51820\n%spublic_key=%s\npreshared_key=%s\nallowed_ip=%s/32\nallowed_ip=%s/128\n",
				wgtest.Hex(s.Key.Private), wgtest.JoinLines(p.Server), wgtest.Hex(client.Public), wgtest.Hex(s.PSK), wgtest.ClientV4, wgtest.ClientV6)
			s.Addr = startReferenceContainer(t, image, tc.server, uapi)

			c := startClient(t, s.ClientText(client, "0.0.0.0/0, ::/0", p.Client...), "")
			echoTCP(t, c, "10.77.0.1:7", 256<<10)
			echoTCP(t, c, "[fd77::1]:7", 64<<10)
			echoUDP(t, c, netip.MustParseAddrPort("10.77.0.1:7"), 1200)
			echoUDP(t, c, netip.MustParseAddrPort("[fd77::1]:7"), 1200)
			// Larger than the tunnel MTU: fragmented inside the tunnel.
			echoUDP(t, c, netip.MustParseAddrPort("10.77.0.1:7"), 8000)

			if tc.profile == "" {
				return
			}
			expectNoHandshake(t, s.ClientText(client, "0.0.0.0/0"))
			if tc.profile == "awg-3.1" {
				var other [32]byte
				if _, err := rand.Read(other[:]); err != nil {
					t.Fatal(err)
				}
				wrong := slices.Clone(p.Client)
				for i, line := range wrong {
					if strings.HasPrefix(line, "HeaderProtectionKey") {
						wrong[i] = "HeaderProtectionKey = " + wgtest.B64(other)
					}
				}
				expectNoHandshake(t, s.ClientText(client, "0.0.0.0/0", wrong...))
			}
		})
	}
}

// expectNoHandshake checks that a client with text never completes a
// handshake.
func expectNoHandshake(t *testing.T, text string) {
	t.Helper()
	cfg, err := wgconf.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Config: cfg, Endpoint: netip.MustParseAddrPort(cfg.Endpoint())})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.WaitHandshake(ctx); err == nil {
		t.Fatal("handshake with mismatched options must not complete")
	}
}

// startReferenceContainer starts server (wireguard-go or amneziawg-go) with
// uapi in a new container and returns its WireGuard endpoint.
func startReferenceContainer(t *testing.T, image, server, uapi string) netip.AddrPort {
	t.Helper()
	socket := map[string]string{"wireguard-go": "/var/run/wireguard/wg0.sock", "amneziawg-go": "/var/run/amneziawg/wg0.sock"}[server]
	var id [6]byte
	_, _ = rand.Read(id[:])
	name := "wgci-" + hex.EncodeToString(id[:])
	// The configuration holds test keys; pass it by environment, not argv.
	if out, err := docker([]string{"WGREF_UAPI=" + uapi}, "run", "--detach", "--name", name,
		"--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=0", "--sysctl", "net.ipv6.conf.default.disable_ipv6=0",
		"--env", "WGREF_UAPI",
		image, "-server", "/"+server, "-socket", socket); err != nil {
		t.Fatalf("docker run: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := docker(nil, "logs", name)
			t.Logf("%s logs:\n%s", server, logs)
		}
		_, _ = docker(nil, "rm", "--force", name)
	})
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		logs, err := docker(nil, "logs", name)
		if err == nil && bytes.Contains(logs, []byte("ready\n")) {
			break
		}
		state, _ := docker(nil, "inspect", "--format", "{{.State.Running}}", name)
		if strings.TrimSpace(string(state)) != "true" || time.Now().After(deadline) {
			t.Fatalf("%s did not become ready", server)
		}
	}
	out, err := docker(nil, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
	if err != nil {
		t.Fatalf("docker inspect: %v: %s", err, out)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("container address %q: %v", out, err)
	}
	return netip.AddrPortFrom(addr, 51820)
}

// docker runs the docker CLI for at most two minutes with extra environment.
func docker(env []string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(os.Environ(), env...)
	return cmd.CombinedOutput()
}
