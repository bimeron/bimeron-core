package androidcore

import (
	"runtime"
	"testing"
	"time"
)

// The app validates profiles with NewSession (or NewSessionWithSSConfSnapshot)
// followed by Stop, never Start. That path must open no sockets and leave no
// goroutines behind.
func TestValidationOnlySessionsLeaveNothingRunning(t *testing.T) {
	const source = "ssconf://example.com/key#Name"
	body := []byte("ss://aes-256-gcm:secret@example.com:8388")
	profiles := []string{
		testProfile,
		"[Profile]\nVersion = 1\n[AccessKey]\nSSConf = " + source + "\n",
		"[Profile]\nVersion = 1\n[AccessKey]\nSSH = ssh://user@example.com:22\n",
		"[Profile]\nVersion = 1\n[AccessKey]\nKey = hysteria2://secret@example.com:443?sni=example.com\n",
		"[Profile]\nVersion = 1\n[AccessKey]\nKey = tuic://00000000-0000-0000-0000-000000000000:secret@example.com:443?sni=example.com&alpn=h3\n",
	}
	protector := &testProtector{allow: true}
	run := func() {
		for _, profile := range profiles {
			s, err := NewSession([]byte(profile), protector)
			if err != nil {
				t.Fatalf("profile rejected: %v\n%s", err, profile)
			}
			if err := s.SetNetwork("wifi", "192.0.2.53"); err != nil {
				t.Fatal(err)
			}
			_ = s.Status()
			_ = s.Events()
			if err := s.Stop(); err != nil {
				t.Fatal(err)
			}
		}
		snapshot, err := NewSSConfSnapshot(source, body)
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewSessionWithSSConfSnapshot([]byte(profiles[1]), snapshot, nil, nil, protector)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Stop(); err != nil {
			t.Fatal(err)
		}
		_ = ValidateConfigWithGeoData([]byte(profiles[0]), nil, nil)
	}
	run() // warm up package-level lazy initialisation
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		run()
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		buf := make([]byte, 1<<16)
		t.Fatalf("validation-only sessions leaked goroutines: %d -> %d\n%s", before, after, buf[:runtime.Stack(buf, true)])
	}
	if calls := protector.calls.Load(); calls != 0 {
		t.Fatalf("validation-only sessions opened %d sockets", calls)
	}
}
