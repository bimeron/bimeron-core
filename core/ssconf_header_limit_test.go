package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bimeron/internal/accesskey"
)

const headerLimitBody = "ss://aes-128-gcm:secret@127.0.0.1:443"

// headerLimitCases pad one response header so the block lands just under the
// cap, just over it, or far over it while still below Go's 10 MiB default.
var headerLimitCases = []struct {
	name string
	pad  int
	ok   bool
}{
	{"under", accesskey.MaxSSConfResponseHeaderBytes - 1024, true},
	{"over", accesskey.MaxSSConfResponseHeaderBytes + 1, false},
	{"far-over", 1 << 20, false},
}

func headerLimitServer(t *testing.T, pad int) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Pad", strings.Repeat("a", pad))
		w.Write([]byte(headerLimitBody))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestResolveSSConfResponseHeaderLimit(t *testing.T) {
	for _, tc := range headerLimitCases {
		t.Run(tc.name, func(t *testing.T) {
			server := headerLimitServer(t, tc.pad)
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			got, err := resolveSSConf(ctx, strings.Replace(server.URL, "https:", "ssconf:", 1), PacketNetwork{}, &tls.Config{RootCAs: roots})
			if ctx.Err() != nil {
				t.Fatal("fetch stalled until the deadline")
			}
			if tc.ok {
				if err != nil || string(got) != headerLimitBody {
					t.Fatalf("result %q: %v", got, err)
				}
			} else if err == nil || got != nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("oversized headers accepted: %q, %v", got, err)
			}
		})
	}
}

func TestResolveOnPathResponseHeaderLimit(t *testing.T) {
	for _, tc := range headerLimitCases {
		t.Run(tc.name, func(t *testing.T) {
			server := headerLimitServer(t, tc.pad)
			cfg := testConfig()
			cfg.ResolveOnNetwork = func(ctx context.Context, roundTrip http.RoundTripper) (Profile, error) {
				transport := roundTrip.(*http.Transport)
				if transport.MaxResponseHeaderBytes != accesskey.MaxSSConfResponseHeaderBytes {
					t.Errorf("MaxResponseHeaderBytes = %d", transport.MaxResponseHeaderBytes)
				}
				transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
				return accesskey.NewResolverWithTransport(transport).Resolve(ctx, "ssconf://"+strings.TrimPrefix(server.URL, "https://"))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _, _, err := resolveOnPath(ctx, cfg, networkPath{})
			if ctx.Err() != nil {
				t.Fatal("resolution stalled until the deadline")
			}
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var stage *stageError
			if !errors.As(err, &stage) || stage.code != "access_key_resolve_failed" || !stage.retry {
				t.Fatalf("error = %v, want retryable access_key_resolve_failed", err)
			}
		})
	}
}
