package core

import (
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

const listenAuthProfile = "[Profile]\nVersion = 1\n\n[AccessKey]\nSS = ss://aes-256-gcm:s@example.com:8388\n\n[Interface]\nMode = proxy\nListen = 127.0.0.1:1080\nListenUsername = alice\nListenPassword = s3cret\n"

func TestProxyBackendRefusesAnonymousClient(t *testing.T) {
	c, err := LoadConfigData([]byte(listenAuthProfile))
	if err != nil {
		t.Fatal(err)
	}
	c.Listen = "127.0.0.1:0"
	s, err := (proxyBackend{}).Open(t.Context(), c, func(string, string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	conn, err := net.DialTimeout("tcp", s.(*proxySession).listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply != [2]byte{5, 0xff} {
		t.Fatalf("anonymous method negotiation: %x, %v", reply, err)
	}
}

func TestListenAuthFromConfig(t *testing.T) {
	c, err := LoadConfigData([]byte(listenAuthProfile))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenUsername != "alice" || c.ListenPassword != "s3cret" {
		t.Fatal("listener credentials were not copied")
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	// Validation does not depend on the mode.
	c.Mode, c.ListenPassword = "vpn", ""
	checkProblem(t, "vpn listen auth", c.validate(), wantProblem{"listen_auth_incomplete", "[Interface] ListenUsername and ListenPassword must be set together", "Interface", "ListenPassword", 0})
}

// A GUI turns authentication off by writing empty values with set_field.
func TestListenAuthCanBeClearedWithSetField(t *testing.T) {
	d := ParseConfigDocument([]byte(listenAuthProfile))
	for _, key := range []string{"ListenUsername", "ListenPassword"} {
		if err := d.SetSectionField("Interface", key, ""); err != nil {
			t.Fatal(err)
		}
	}
	c, err := LoadConfigData(d.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenUsername != "" || c.ListenPassword != "" {
		t.Fatal("cleared credentials are still set")
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSOCKSAuthCapability(t *testing.T) {
	b, err := json.Marshal(PlatformCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		SOCKSAuth bool `json:"socks_auth"`
	}
	if err := json.Unmarshal(b, &report); err != nil || !report.SOCKSAuth {
		t.Fatal("socks_auth is not reported", err)
	}
}
