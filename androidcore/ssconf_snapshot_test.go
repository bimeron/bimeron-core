package androidcore

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type snapshotTransport struct{}

func (snapshotTransport) RoundTrip(*http.Request) (*http.Response, error) {
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
				q, f := s.config.ResolveOnNetwork(context.Background(), snapshotTransport{})
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
	p.SSPlugin.Host = "mutated"
	q, err := s.config.ResolveOnNetwork(context.Background(), snapshotTransport{})
	if err != nil || q.SSPlugin.Host == "mutated" || snapshot.profile.SSPlugin.Host == "mutated" {
		t.Fatal("plugin alias")
	}
}
