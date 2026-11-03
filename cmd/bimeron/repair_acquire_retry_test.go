package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type acquisitionTransport func(*http.Request) (*http.Response, error)

func (f acquisitionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRepairAcquisitionCrashRetry(t *testing.T) {
	target := filepath.Join(t.TempDir(), "wintun.dll")
	stale := target + ".repair-download"
	if err := os.WriteFile(stale, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := stageRepairDownload(target, []byte("partial"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := stageRepairDownload(target, []byte("complete"))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("reused crashed attempt")
	}
	for p, want := range map[string]string{stale: "partial", first: "partial", second: "complete"} {
		b, e := os.ReadFile(p)
		if e != nil || string(b) != want {
			t.Fatalf("%s: %q %v", p, b, e)
		}
	}
}
func TestRepairAcquisitionCanonicalVersion(t *testing.T) {
	for _, v := range []string{"01.2.3", "1.02.3", "1.2.03", "1.2.3-", "1.2.3-beta..1", "1.2.3-beta.01", "1.2.3-dev", "1.2.3+local"} {
		if repairReleaseVersion.MatchString(v) {
			t.Fatal(v)
		}
	}
	for _, v := range []string{"0.2.0", "0.2.0-beta.1"} {
		if !repairReleaseVersion.MatchString(v) {
			t.Fatal(v)
		}
	}
}
func TestRepairAcquisitionHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, location, body string
		length               int64
	}{
		{"redirect", "https://evil.example/payload", "", 0},
		{"downgrade", "http://github.com/payload", "", 0},
		{"loop", "https://github.com/again", "", 0},
		{"declared", "", "x", 10},
		{"streamed", "", "12345", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := newRepairHTTPClient(acquisitionTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Host != "github.com" {
					t.Fatal("contacted rejected host")
				}
				h := make(http.Header)
				status := 200
				if tc.location != "" {
					status = 302
					h.Set("Location", tc.location)
				}
				return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(tc.body)), ContentLength: tc.length, Request: r}, nil
			}))
			if _, err := fetchRepairBytes(context.Background(), c, "https://github.com/start", 4); err == nil {
				t.Fatal("accepted")
			}
			if calls > 4 {
				t.Fatal("redirect budget exceeded")
			}
		})
	}
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c := newRepairHTTPClient(acquisitionTransport(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() }))
		if _, err := fetchRepairBytes(ctx, c, "https://github.com/start", 4); err == nil {
			t.Fatal("ignored cancellation")
		}
	})
}
