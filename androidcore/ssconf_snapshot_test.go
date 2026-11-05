package androidcore

import (
	"bimeron/core"
	"bimeron/internal/accesskey"
	"bimeron/internal/routing"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type snapshotTransport struct{ t *testing.T }

func (s snapshotTransport) RoundTrip(*http.Request) (*http.Response, error) {
	s.t.Error("unexpected HTTP request")
	return nil, errors.New("network forbidden")
}

func TestSnapshotPinned(t *testing.T) {
	source := "ssconf://example.com/key#Display%20Name"
	body := []byte("ss://aes-256-gcm:secret@example.com:8388")
	snapshot, err := NewSSConfSnapshot(" "+source+" ", body)
	if err != nil {
		t.Fatal(err)
	}
	body[0] = 'x'
	profile := []byte("[Profile]\nVersion = 1\n[AccessKey]\nSSConf = " + source + "\n")
	protector := &testProtector{}
	s, err := NewSessionWithSSConfSnapshot(profile, snapshot, nil, nil, protector)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	keySession, err := NewSessionWithSSConfSnapshot(bytes.Replace(profile, []byte("SSConf ="), []byte("Key ="), 1), snapshot, nil, nil, protector)
	if err != nil {
		t.Fatal(err)
	}
	defer keySession.Stop()
	p, err := keySession.config.ResolveOnNetwork(context.Background(), snapshotTransport{t})
	if err != nil || p.TCP.Host != "example.com" || p.Name != "Display Name" {
		t.Fatal("exact Key binding failed", err)
	}
	profile[0] = 'x'
	if protector.calls.Load() != 0 || s.auth.id == "" {
		t.Fatal("construction side effects or missing auth")
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				p, e := s.config.Resolve(context.Background())
				q, f := s.config.ResolveOnNetwork(context.Background(), snapshotTransport{t})
				if e != nil || f != nil || p.TCP.Host != "example.com" || q.Name != "Display Name" {
					t.Errorf("invalid fixed resolution")
				}
			}
		}()
	}
	wg.Wait()
	for _, other := range []string{source + "x", strings.Replace(source, "example", "Example", 1), strings.Replace(source, "%20", " ", 1), "\ufeff" + source} {
		cfg := []byte("[Profile]\nVersion = 1\n[AccessKey]\nKey = " + other + "\n")
		if got, e := NewSessionWithSSConfSnapshot(cfg, snapshot, nil, nil, protector); e == nil || got != nil {
			t.Fatal("accepted mismatch")
		}
	}
}

func TestSnapshotValidation(t *testing.T) {
	for _, body := range []string{
		`{"server":"example.com","server_port":8388,"method":"aes-256-gcm","password":"secret","plugin":"obfs-local","plugin_opts":"obfs=http"}`,
		"ss://aes-256-gcm:secret@example.com:8388",
		"server: example.com\nserver_port: 8388\nmethod: aes-256-gcm\npassword: secret\n",
	} {
		if _, err := NewSSConfSnapshot("ssconf://example.com/key", []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	valid := "ss://aes-256-gcm:secret@example.com:8388"
	if _, err := NewSSConfSnapshot("ssconf://example.com", []byte(valid+strings.Repeat(" ", 65536-len(valid)))); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"", strings.Repeat("x", 65537), "ssconf://secret", testProfile, "password: secret"} {
		got, err := NewSSConfSnapshot("ssconf://example.com", []byte(body))
		if got != nil || err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("unsafe rejection")
		}
	}
	for _, source := range []string{"SSCONF://example.com", "\ufeffssconf://example.com", "ssconf://user@example.com", "ssconf://example.com:0"} {
		if got, err := NewSSConfSnapshot(source, []byte(valid)); got != nil || err == nil {
			t.Fatal("invalid source accepted")
		}
	}
	for _, snapshot := range []*SSConfSnapshot{nil, {}} {
		if got, err := NewSessionWithSSConfSnapshot(nil, snapshot, nil, nil, &testProtector{}); got != nil || err == nil {
			t.Fatal("invalid snapshot accepted")
		}
	}
}

func TestSnapshotPluginIsolation(t *testing.T) {
	snapshot, err := NewSSConfSnapshot("ssconf://example.com", []byte("ss://aes-256-gcm:secret@example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSessionWithSSConfSnapshot([]byte("[Profile]\nVersion = 1\n[AccessKey]\nSSConf = ssconf://example.com\n"), snapshot, nil, nil, &testProtector{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	p, err := s.config.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expected := *p.SSPlugin
	p.SSPlugin.Host = "mutated"
	q, err := s.config.ResolveOnNetwork(context.Background(), snapshotTransport{t})
	if err != nil || !reflect.DeepEqual(*q.SSPlugin, expected) || !reflect.DeepEqual(*snapshot.profile.SSPlugin, expected) {
		t.Fatal("plugin alias")
	}
}

func TestSnapshotOfflineReloadAndDistinctTransports(t *testing.T) {
	oldTransport, oldResolver := http.DefaultTransport, net.DefaultResolver
	http.DefaultTransport = snapshotTransport{t}
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		t.Error("unexpected DNS resolution")
		return nil, errors.New("DNS forbidden")
	}}
	t.Cleanup(func() { http.DefaultTransport = oldTransport; net.DefaultResolver = oldResolver })
	bodies := []string{
		`{"transport":{"$type":"tcpudp","tcp":{"$type":"shadowsocks","endpoint":"tcp.invalid:8388","cipher":"aes-256-gcm","secret":"tcp-secret","prefix":"TCP"},"udp":{"$type":"shadowsocks","endpoint":"udp.invalid:8389","cipher":"chacha20-ietf-poly1305","secret":"udp-secret","prefix":"UDP"}}}`,
		"transport:\n  $type: tcpudp\n  tcp:\n    $type: shadowsocks\n    endpoint: tcp.invalid:8388\n    cipher: aes-256-gcm\n    secret: tcp-secret\n    prefix: TCP\n  udp:\n    $type: shadowsocks\n    endpoint: udp.invalid:8389\n    cipher: chacha20-ietf-poly1305\n    secret: udp-secret\n    prefix: UDP\n",
	}
	for _, body := range bodies {
		t.Run(body[:9], func(t *testing.T) {
			raw := []byte(" \n" + body + "\n ")
			expected, err := accesskey.ParseConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			expected.Name = "Pinned Name"
			source := "ssconf://source.invalid/key#Pinned%20Name"
			snap, err := NewSSConfSnapshot("\t "+source+"\n", raw)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(snap.content, raw) || snap.source != source {
				t.Fatal("raw reload identity changed")
			}
			reload, err := NewSSConfSnapshot(source, append([]byte(nil), raw...))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(snap, reload) {
				t.Fatal("reload changed snapshot")
			}
			raw[0] = '!'
			if broken, e := NewSSConfSnapshot(source, raw[:7]); e == nil || broken != nil {
				t.Fatal("corrupted reload accepted")
			}
			cfg := []byte("[Profile]\nVersion = 1\n[AccessKey]\nSSConf = " + source + "\n")
			protector := &testProtector{}
			session, err := NewSessionWithSSConfSnapshot(cfg, reload, nil, nil, protector)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Stop()
			cfg[0] = '!'
			for i := 0; i < 5; i++ {
				a, e := session.config.Resolve(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				b, e := session.config.ResolveOnNetwork(context.Background(), snapshotTransport{t})
				if e != nil {
					t.Fatal(e)
				}
				if !reflect.DeepEqual(a, expected) || !reflect.DeepEqual(b, expected) {
					t.Fatalf("fixed transport mismatch: %#v %#v", a, b)
				}
			}
			if protector.calls.Load() != 0 || !strings.Contains(session.Status(), "disconnected") {
				t.Fatal("constructor started session")
			}
		})
	}
}

func TestSnapshotBindingFailuresAndShadowTLS(t *testing.T) {
	const base = "[Profile]\nVersion = 1\n[AccessKey]\nSSConf = ssconf://source.invalid/key\n"
	snap, err := NewSSConfSnapshot("ssconf://source.invalid/key", []byte("ss://aes-256-gcm:private-secret@server.invalid:443"))
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []string{
		"[Profile]\nVersion = 1\n", testProfile,
		base + "SS = ss://aes-256-gcm:private-secret@server.invalid:443\n",
		base + "File = private-secret\n", base + "[Interface]\nMode = proxy\n",
		base + "[Interface]\nKillSwitch = true\n", base + "[ShadowTLS]\nServerName = bad/name\nPassword = private-secret\n",
		base + "[private-secret]\nunknown = private-secret\n",
	} {
		got, e := NewSessionWithSSConfSnapshot([]byte(cfg), snap, nil, nil, &testProtector{})
		if got != nil || e == nil {
			if got != nil {
				got.Stop()
			}
			t.Fatalf("accepted invalid configuration %q", cfg)
		}
		if strings.Contains(e.Error(), "private-secret") {
			t.Fatal("diagnostics leaked")
		}
	}
	if got, e := NewSessionWithSSConfSnapshot([]byte(base), snap, nil, nil, nil); got != nil || e == nil {
		t.Fatal("nil protector accepted")
	}
	cfg := []byte(base + "[ShadowTLS]\nServerName = cover.invalid\nPassword = outer-secret\n")
	s, e := NewSessionWithSSConfSnapshot(cfg, snap, nil, nil, &testProtector{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Stop()
	for i := 0; i < 3; i++ {
		p, e := s.config.Resolve(context.Background())
		if e != nil || p.ShadowTLS == nil || p.ShadowTLS.Password != "outer-secret" || !p.TCPOnly() {
			t.Fatal("wrapper lost", e)
		}
		p.ShadowTLS.Password = "changed"
		q, e := s.config.ResolveOnNetwork(context.Background(), snapshotTransport{t})
		if e != nil || q.ShadowTLS.Password != "outer-secret" {
			t.Fatal("wrapper aliased", e)
		}
	}
	incompatible, e := NewSSConfSnapshot(snap.source, []byte("ss://aes-192-gcm:private-secret@server.invalid:443"))
	if e != nil {
		t.Fatal(e)
	}
	if got, e := NewSessionWithSSConfSnapshot(cfg, incompatible, nil, nil, &testProtector{}); got != nil || e == nil {
		if got != nil {
			got.Stop()
		}
		t.Fatal("incompatible wrapper accepted")
	}
}

func TestSnapshotOriginalConfigurationAndAuth(t *testing.T) {
	source := "ssconf://source.invalid/key#name"
	raw := []byte("[Profile]\nVersion = 1\nName = Original\n[AccessKey]\nSSConf = " + source + "\n[Interface]\nName = original-interface\nMTU = 1380\nDNS = 9.9.9.9, 1.1.1.1\nIPv6 = disable\n[Rule]\nGeoIP = test\nAction = direct\n[Rule]\nGeoSite = test\nAction = direct\n")
	field := func(n byte, b []byte) []byte {
		out := binary.AppendUvarint([]byte{n<<3 | 2}, uint64(len(b)))
		return append(out, b...)
	}
	cidr := append(field(1, []byte{203, 0, 113, 0}), 16, 24)
	ip := field(1, append(field(1, []byte("TEST")), field(2, cidr)...))
	domain := append([]byte{8, 2}, field(2, []byte("example.org"))...)
	site := field(1, append(field(1, []byte("TEST")), field(2, domain)...))
	expected, e := core.LoadConfigDataWithGeoData(raw, ip, site)
	if e != nil {
		t.Fatal(e)
	}
	snap, e := NewSSConfSnapshot(source, []byte("ss://aes-256-gcm:secret@host.invalid:443"))
	if e != nil {
		t.Fatal(e)
	}
	protector := &testProtector{}
	s, e := NewSessionWithSSConfSnapshot(raw, snap, ip, site, protector)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Stop()
	clear(raw)
	clear(ip)
	clear(site)
	for _, tc := range []struct {
		ip, domain string
		want       routing.Action
	}{
		{"203.0.113.9", "", routing.Direct},
		{"192.0.2.1", "www.example.org", routing.Direct},
		{"192.0.2.1", "unmatched.invalid", routing.Proxy},
	} {
		if got := s.config.Policy.Decide(netip.MustParseAddr(tc.ip), tc.domain); got != tc.want {
			t.Fatalf("routing after mutation: %v, want %v", got, tc.want)
		}
	}
	a, b := s.config, expected
	a.Resolve = nil
	a.ResolveOnNetwork = nil
	b.Resolve = nil
	b.ResolveOnNetwork = nil
	if !reflect.DeepEqual(a, b) {
		t.Fatal("original runtime configuration changed")
	}
	if s.auth.id == "" || s.generation != 0 || s.networkID != "" || s.config.SSHPrompt != nil || protector.calls.Load() != 0 {
		t.Fatal("invalid initial auth/network state")
	}
	if _, e := s.outbound(context.Background()); e == nil {
		t.Fatal("network available before selection")
	}
	if e := s.SetNetwork("physical", "1.1.1.1"); e != nil {
		t.Fatal(e)
	}
	network, e := s.outbound(context.Background())
	if e != nil || network.SSHPrompt == nil {
		t.Fatal("generation prompt missing", e)
	}
	if protector.calls.Load() != 0 {
		t.Fatal("outbound creation invoked protector")
	}
}

func TestSnapshotSourcePorts(t *testing.T) {
	for _, host := range []string{"example.com", "[2001:db8::1]"} {
		for _, port := range []string{"", ":", ":443", ":0", ":invalid", ":65536"} {
			t.Run(host+port, func(t *testing.T) {
				source := "ssconf://" + host + port + "/private-key#private-name"
				got, err := NewSSConfSnapshot(source, []byte("ss://aes-256-gcm:private-secret@example.com:8388"))
				if port == "" || port == ":443" {
					if err != nil || got == nil {
						t.Fatal("valid source rejected", err)
					}
				} else if got != nil || err == nil || err.Error() != "invalid SSConf snapshot source" {
					t.Fatal("expected nil snapshot and redacted source error")
				}
			})
		}
	}
}
