package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionInfoLifecycleAndSnapshotIsolation(t *testing.T) {
	e := testEngine(fakeBackend{open: func(context.Context) (session, error) { return fakeSession{}, nil }})
	if e.Status().Session != nil {
		t.Fatal("session exists before Start")
	}
	c := testConfig()
	c.ProfileName = "Main"
	c.ProfileID = strings.Repeat("a", 64)
	c.KillSwitch = true
	c.DisableIPv6 = true
	ctx := testDeadline(t)
	defer e.Stop(context.Background())
	if err := e.Start(ctx, c); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Connected)
	info := e.Status().Session
	if info == nil || !info.Active || info.ProfileName != "Main" || info.ProfileID != c.ProfileID || info.IPv6 != "disable" || !info.KillSwitchRequested {
		t.Fatal(info)
	}
	oldID := info.ID
	info.ProfileName = "mutation"
	if e.Status().Session.ProfileName != "Main" {
		t.Fatal("mutable snapshot")
	}
	if err := e.Start(ctx, c); err == nil {
		t.Fatal("double start accepted")
	}
	if e.Status().Session.ID != oldID {
		t.Fatal("rejected Start replaced identity")
	}
	if err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if e.Status().Session.Active || e.Status().Session.ID != oldID {
		t.Fatal("wrong stopped metadata")
	}
	if err := e.Start(ctx, c); err != nil {
		t.Fatal(err)
	}
	if e.Status().Session.ID == oldID {
		t.Fatal("new Start reused ID")
	}
}
func TestSessionInfoExcludesKeyAndResolver(t *testing.T) {
	c := testConfig()
	c.ProfileName = "Label\nTest"
	c.ProfileID = "ssconf://private.example/secret"
	info, err := newSessionInfo(c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "private.example") || info.ProfileName != "LabelTest" {
		t.Fatal(string(b))
	}
}

func TestSessionEndpointSnapshotIsolation(t *testing.T) {
	e := testEngine(fakeBackend{openConfig: func(_ context.Context, c SessionConfig) (session, error) {
		c.endpointChanged(sessionEndpoints{tcp: "192.0.2.1:443", udp: "192.0.2.2:53", tcpName: "tcp.example", udpName: "udp.example"})
		return fakeSession{}, nil
	}})
	ctx := testDeadline(t)
	defer e.Stop(context.Background())
	if err := e.Start(ctx, testConfig()); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, Connected)
	info := e.Status().Session
	if info == nil || info.ServerTCP != "192.0.2.1:443" || info.ServerUDP != "192.0.2.2:53" || info.ServerTCPName != "tcp.example" || info.ServerUDPName != "udp.example" {
		t.Fatal(info)
	}
	info.ServerTCP = "mutation"
	if e.Status().Session.ServerTCP != "192.0.2.1:443" {
		t.Fatal("mutable endpoint snapshot")
	}
}
func TestProfileIdentityStableAndPathFree(t *testing.T) {
	path := t.TempDir() + "/main.conf"
	a, err := ProfileIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ProfileIdentity(path)
	if err != nil || a != b || len(a) != 64 || strings.Contains(a, "main") {
		t.Fatal(a, b, err)
	}
}

func TestLoadConfigCarriesProfileIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "main.conf")
	contents := "[Profile]\nVersion = 1\nName = Main\n[AccessKey]\nSS = ss://aes-256-gcm:test-secret@127.0.0.1:8388\n[Interface]\nMode = vpn\nIPv6 = disable\nKillSwitch = true\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ProfileIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := newSessionInfo(c)
	if err != nil {
		t.Fatal(err)
	}
	if info.ProfileID != want || info.ProfileName != "Main" || info.IPv6 != "disable" || !info.KillSwitchRequested {
		t.Fatal(info)
	}
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "test-secret") || strings.Contains(string(data), path) {
		t.Fatal("metadata exposes key or path")
	}
}
