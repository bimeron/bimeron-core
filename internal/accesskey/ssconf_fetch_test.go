package accesskey

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetchSSConfValidatedBytes(t *testing.T) {
	valid := "ss://aes-128-gcm:secret@127.0.0.1:443"
	padded := "server: 127.0.0.1\nserver_port: 443\nmethod: aes-128-gcm\npassword: secret\n#"
	padded += strings.Repeat("x", 65536-len(padded))
	if _, err := ParseConfig([]byte(padded)); err != nil {
		t.Fatalf("invalid boundary fixture: %v", err)
	}
	for _, body := range []string{valid, padded, "invalid secret", padded + "x"} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		resolver := NewResolverWithTransport(server.Client().Transport)
		b, profile, err := resolver.FetchSSConf(context.Background(), strings.Replace(server.URL, "https://", "ssconf://", 1)+"/secret")
		server.Close()
		if body == valid || body == padded {
			if err != nil || string(b) != body {
				t.Fatalf("valid fetch failed: %v", err)
			}
		} else if err == nil || b != nil || !reflect.DeepEqual(profile, Profile{}) || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid bytes published")
		}
	}
}
func TestFetchSSConfRedirectPolicy(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1/secret", "https://user:secret@127.0.0.1/", "/loop"} {
		var requests atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			http.Redirect(w, r, target, http.StatusFound)
		}))
		b, _, err := NewResolverWithTransport(server.Client().Transport).FetchSSConf(context.Background(), strings.Replace(server.URL, "https://", "ssconf://", 1))
		server.Close()
		wantRequests := int32(1)
		if target == "/loop" {
			wantRequests = 5
		}
		if got := requests.Load(); got != wantRequests {
			t.Fatalf("requests = %d, want %d", got, wantRequests)
		}
		if err == nil || b != nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("redirect policy or redaction failed")
		}
	}
}

func TestFetchSSConfRedirectBoundary(t *testing.T) {
	for _, redirects := range []int{4, 5} {
		t.Run(fmt.Sprint(redirects), func(t *testing.T) {
			const valid = "ss://aes-128-gcm:secret@127.0.0.1:443"
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := int(requests.Add(1))
				if n <= redirects {
					http.Redirect(w, r, fmt.Sprintf("/secret/%d", n), http.StatusFound)
					return
				}
				w.Write([]byte(valid))
			}))
			defer server.Close()
			b, profile, err := NewResolverWithTransport(server.Client().Transport).FetchSSConf(context.Background(), strings.Replace(server.URL, "https://", "ssconf://", 1))
			if got := requests.Load(); got != 5 {
				t.Fatalf("requests = %d, want 5", got)
			}
			if redirects == 4 {
				if err != nil || string(b) != valid {
					t.Fatalf("four redirects failed: %v", err)
				}
			} else if err == nil || b != nil || !reflect.DeepEqual(profile, Profile{}) || strings.Contains(err.Error(), "secret") {
				t.Fatal("fifth redirect rejection or redaction failed")
			}
		})
	}
}

func TestNewResolverResponseHeaderLimit(t *testing.T) {
	transport, ok := NewResolver().client.Transport.(*http.Transport)
	if !ok || transport == http.DefaultTransport || transport.MaxResponseHeaderBytes != MaxSSConfResponseHeaderBytes {
		t.Fatal("NewResolver does not use a capped DefaultTransport clone")
	}
	defaults := http.DefaultTransport.(*http.Transport)
	if defaults.MaxResponseHeaderBytes != 0 || transport.Proxy == nil || transport.ForceAttemptHTTP2 != defaults.ForceAttemptHTTP2 ||
		transport.TLSHandshakeTimeout != defaults.TLSHandshakeTimeout || transport.IdleConnTimeout != defaults.IdleConnTimeout {
		t.Fatal("NewResolver transport diverged from DefaultTransport")
	}
	const valid = "ss://aes-128-gcm:secret@127.0.0.1:443"
	for _, tc := range []struct {
		pad int
		ok  bool
	}{{MaxSSConfResponseHeaderBytes - 1024, true}, {MaxSSConfResponseHeaderBytes + 1, false}, {1 << 20, false}} {
		t.Run(fmt.Sprint(tc.pad), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Pad", strings.Repeat("a", tc.pad))
				w.Write([]byte(valid))
			}))
			defer server.Close()
			// Trust the test certificate on a clone of NewResolver's own transport.
			r := NewResolver()
			trusted := r.client.Transport.(*http.Transport).Clone()
			trusted.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			defer trusted.CloseIdleConnections()
			r.client.Transport = trusted
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			b, profile, err := r.FetchSSConf(ctx, strings.Replace(server.URL, "https://", "ssconf://", 1)+"/secret")
			if ctx.Err() != nil {
				t.Fatal("fetch stalled until the deadline")
			}
			if tc.ok {
				if err != nil || string(b) != valid {
					t.Fatalf("result %q: %v", b, err)
				}
			} else if err == nil || b != nil || !reflect.DeepEqual(profile, Profile{}) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("oversized headers accepted: %q, %v", b, err)
			}
		})
	}
}

type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

type handshakeTimeout struct{}

func (handshakeTimeout) Error() string   { return "net/http: TLS handshake timeout" }
func (handshakeTimeout) Timeout() bool   { return true }
func (handshakeTimeout) Temporary() bool { return true }

// A failed lookup of the ssconf host is a network failure that is also marked
// as DNS; a handshake timeout is a network failure. Neither exposes the URL.
func TestFetchSSConfClassifiesDNSAndTimeouts(t *testing.T) {
	const key = "ssconf://private.example/private-key?token=secret"
	for _, tc := range []struct {
		name string
		err  error
		dns  bool
	}{
		{"dns", &net.DNSError{Err: "no such host", Name: "private.example", IsNotFound: true}, true},
		{"handshake timeout", handshakeTimeout{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := NewResolverWithTransport(failingTransport{tc.err}).FetchSSConf(context.Background(), key)
			if err == nil || err.Error() != "could not fetch dynamic config" || !errors.Is(err, ErrSSConfNetwork) || errors.Is(err, ErrSSConfDNS) != tc.dns {
				t.Fatalf("unexpected classification: %v", err)
			}
			var raw *url.Error
			if errors.As(err, &raw) || strings.Contains(err.Error(), "private") {
				t.Fatalf("diagnostic exposes the request: %v", err)
			}
		})
	}
}
