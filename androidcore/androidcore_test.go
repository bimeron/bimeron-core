package androidcore

import (
	"context"
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
