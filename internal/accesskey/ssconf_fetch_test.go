package accesskey

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchSSConfValidatedBytes(t *testing.T) {
	valid := "ss://aes-128-gcm:secret@127.0.0.1:443"
	for _, body := range []string{valid, "invalid secret", strings.Repeat("x", 65537)} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		resolver := NewResolverWithTransport(server.Client().Transport)
		b, _, err := resolver.FetchSSConf(context.Background(), strings.Replace(server.URL, "https://", "ssconf://", 1)+"/secret")
		server.Close()
		if body == valid {
			if err != nil || string(b) != valid {
				t.Fatalf("valid fetch failed: %v", err)
			}
		} else if err == nil || b != nil {
			t.Fatal("invalid bytes published")
		}
	}
}
func TestFetchSSConfRedirectPolicy(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1/secret", "https://user:secret@127.0.0.1/", "/loop"} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target, http.StatusFound) }))
		b, _, err := NewResolverWithTransport(server.Client().Transport).FetchSSConf(context.Background(), strings.Replace(server.URL, "https://", "ssconf://", 1))
		server.Close()
		if err == nil || b != nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("redirect policy or redaction failed")
		}
	}
}
