package androidcore

import (
	"bimeron/core"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testProfile = "[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://aes-256-gcm:secret@example.com:8388\n"

type testProtector struct {
	allow bool
	calls atomic.Int32
}

func (p *testProtector) Protect(int) bool { p.calls.Add(1); return p.allow }

func TestProtectedOutbound(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, allow := range []bool{false, true} {
		protector := &testProtector{allow: allow}
		s, err := NewSession([]byte(testProfile), protector)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.outbound(context.Background()); err == nil {
			t.Fatal("outbound available before physical network")
		}
		if err := s.SetNetwork("wifi", "192.0.2.53"); err != nil {
			t.Fatal(err)
		}
		path, err := s.outbound(context.Background())
		if err != nil || path.Identity != "wifi:1" || len(path.DNS) != 1 {
			t.Fatal(path, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, dialErr := path.Dialer.DialContext(ctx, "tcp4", listener.Addr().String())
		cancel()
		if conn != nil {
			conn.Close()
		}
		if protector.calls.Load() == 0 || (dialErr == nil) != allow {
			t.Fatal("socket protection was bypassed", allow, dialErr)
		}
		if err := s.SetNetwork("wifi", "192.0.2.53"); err != nil {
			t.Fatal(err)
		}
		path, _ = s.outbound(context.Background())
		if path.Identity != "wifi:1" {
			t.Fatal("unchanged network forced reconnect", path.Identity)
		}
		if err := s.SetNetwork("mobile", ""); err != nil {
			t.Fatal(err)
		}
		path, _ = s.outbound(context.Background())
		if path.Identity != "mobile:2" {
			t.Fatal("network change was missed", path.Identity)
		}
		if err := s.Stop(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAndroidSessionValidation(t *testing.T) {
	protector := &testProtector{allow: true}
	if _, err := NewSession([]byte(testProfile), nil); err == nil {
		t.Fatal("missing socket protector accepted")
	}
	if _, err := NewSession([]byte(testProfile+"[Interface]\nKillSwitch = true\n"), protector); err == nil {
		t.Fatal("unsupported kill switch accepted")
	}
	if _, err := NewSession([]byte(testProfile+"[Interface]\nMode = proxy\n"), protector); err == nil {
		t.Fatal("proxy config accepted")
	}
	s, err := NewSession([]byte(testProfile), protector)
	if err != nil {
		t.Fatal(err)
	}
	for _, dns := range []string{"invalid", "::1", "1.1.1.1,"} {
		if err := s.SetNetwork("wifi", dns); err == nil {
			t.Fatal("invalid physical DNS accepted", dns)
		}
	}
	if !strings.Contains(s.Status(), "disconnected") || s.MTU() != 1420 {
		t.Fatal("invalid initial status or settings")
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err == nil {
		t.Fatal("stopped session restarted")
	}
}

func TestGeoDataBindings(t *testing.T) {
	var caps map[string]any
	if err := json.Unmarshal([]byte(Capabilities()), &caps); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"geoip_split", "geosite_split"} {
		if caps[key] != true {
			t.Fatalf("missing capability %s: %v", key, caps)
		}
	}
	if caps["geodata_schema"] == "" || caps["geodata_schema"] == nil {
		t.Fatal(caps)
	}
	var result struct {
		Groups []string `json:"groups"`
		Error  *string  `json:"error"`
	}
	for _, input := range []struct {
		profile string
		valid   bool
	}{
		{testProfile, true},
		{testProfile + "[Interface]\nKillSwitch = true\n", false},
		{testProfile + "[Interface]\nMode = proxy\n", false},
		{"invalid", false},
	} {
		if err := json.Unmarshal([]byte(ValidateConfigWithGeoData([]byte(input.profile), nil, nil)), &result); err != nil {
			t.Fatal(err)
		}
		if (result.Error == nil) != input.valid {
			t.Fatalf("validation: %+v", result)
		}
	}
	if err := json.Unmarshal([]byte(GeoDataGroups("invalid", nil)), &result); err != nil {
		t.Fatal(err)
	}
	if result.Error == nil || result.Groups == nil {
		t.Fatalf("groups: %+v", result)
	}
	protector := &testProtector{allow: true}
	s, err := NewSessionWithGeoData([]byte(testProfile), nil, nil, protector)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSessionWithGeoData([]byte(testProfile+"[Interface]\nKillSwitch = true\n"), nil, nil, protector); err == nil {
		t.Fatal("kill switch accepted")
	}
}

func TestGeoDataGroupSuccess(t *testing.T) {
	// GeoIPList containing one empty group named TEST.
	data := []byte{10, 6, 10, 4, 'T', 'E', 'S', 'T'}
	if got := GeoDataGroups("geoip", data); got != `{"groups":["test"],"error":null}` {
		t.Fatal(got)
	}
	if got := GeoDataGroups("geoip", nil); got != `{"groups":[],"error":null}` {
		t.Fatal(got)
	}
}

func TestGeoDataErrorDetails(t *testing.T) {
	var result struct {
		Error   *string            `json:"error"`
		Details *core.GeoDataError `json:"details"`
	}
	if err := json.Unmarshal([]byte(GeoDataGroups("geoip", []byte{255})), &result); err != nil {
		t.Fatal(err)
	}
	if result.Error == nil || result.Details == nil || result.Details.Code != "geodata_invalid" || result.Details.Kind != "geoip" {
		t.Fatalf("%+v", result)
	}
	wrapped := fmt.Errorf("wrapped: %w", &core.GeoDataError{Code: "geodata_group_unknown", Kind: "geoip", Group: "missing", Rule: 2, Err: errors.New("unknown group")})
	if err := json.Unmarshal([]byte(geoDataJSON(nil, wrapped)), &result); err != nil {
		t.Fatal(err)
	}
	if result.Details == nil || result.Details.Rule != 2 || result.Details.Group != "missing" {
		t.Fatalf("%+v", result)
	}
	if err := json.Unmarshal([]byte(geoDataJSON(nil, errors.New("generic"))), &result); err != nil {
		t.Fatal(err)
	}
	// Unmarshal a fresh value to check omission rather than retaining prior fields.
	var generic map[string]any
	if err := json.Unmarshal([]byte(geoDataJSON(nil, errors.New("generic"))), &generic); err != nil {
		t.Fatal(err)
	}
	if _, ok := generic["details"]; ok {
		t.Fatal(generic)
	}
}

func TestEmbeddedGeoDataRestrictions(t *testing.T) {
	ip := []byte{10, 6, 10, 4, 'T', 'E', 'S', 'T'}
	profile := testProfile + "[Rule]\nGeoIP = test\nAction = direct\n"
	s, err := NewSessionWithGeoData([]byte(profile), ip, nil, &testProtector{allow: true})
	if err != nil {
		t.Fatal(err)
	}
	clear(ip)
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	ikev2 := "[Profile]\nVersion = 1\n[IKEv2]\nWindowsProfile = Corporate VPN\nServerName = vpn.example.com\n[Interface]\nMode = vpn\n"
	if _, err := NewSessionWithGeoData([]byte(ikev2), nil, nil, &testProtector{allow: true}); err == nil {
		t.Fatal("IKEv2 accepted")
	}
	var result struct {
		Error   *string            `json:"error"`
		Details *core.GeoDataError `json:"details"`
	}
	if err := json.Unmarshal([]byte(ValidateConfigWithGeoData([]byte(ikev2), nil, nil)), &result); err != nil {
		t.Fatal(err)
	}
	if result.Error == nil {
		t.Fatal("IKEv2 validation accepted")
	}
	ip = []byte{10, 6, 10, 4, 'T', 'E', 'S', 'T'}
	profile = testProfile + "[Rule]\nCIDR = 192.0.2.0/24\nAction = direct\n[Rule]\nGeoIP = missing\nAction = direct\n"
	if err := json.Unmarshal([]byte(ValidateConfigWithGeoData([]byte(profile), ip, nil)), &result); err != nil {
		t.Fatal(err)
	}
	if result.Details == nil || result.Details.Code != "geodata_group_unknown" || result.Details.Rule != 2 || result.Details.Group != "missing" {
		t.Fatalf("%+v", result)
	}
}
