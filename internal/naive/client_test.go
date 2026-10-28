package naive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCancelPendingConnect(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			started := make(chan struct{})
			profile, roots, _ := testProxy(t, protocol, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host == "pending.example:443" {
					close(started)
					<-r.Context().Done()
					return
				}
				echoTunnel(w, r)
			}))
			client, err := New(profile, net.Dialer{})
			if err != nil {
				t.Fatal(err)
			}
			client.rootCAs = roots
			defer client.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			setup, stop := context.WithCancel(ctx)
			defer stop()
			result := make(chan error, 1)
			go func() { _, err := client.DialStream(setup, "pending.example:443"); result <- err }()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			stop()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("setup cancellation lost: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("pending CONNECT was not canceled")
			}
			conn, err := client.DialStream(ctx, "example.org:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("stream deadline did not cancel the read")
			}
		})
	}
}

func TestConnect(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			for _, padded := range []bool{false, true} {
				t.Run(map[bool]string{false: "ordinary", true: "padded"}[padded], func(t *testing.T) {
					profile, roots, connections := testProxy(t, protocol, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if (r.ProtoMajor == 3) != (protocol == "h3") || r.Method != http.MethodConnect || (r.Host != "example.org:443" && r.Host != "example.org:8443") || r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" || r.Header.Get("Padding") == "" || r.Header.Get("Authorization") != "" {
							w.WriteHeader(http.StatusProxyAuthRequired)
							return
						}
						if padded {
							w.Header().Set("Padding", "reply-padding")
						}
						w.WriteHeader(http.StatusOK)
						w.(http.Flusher).Flush()
						buf := make([]byte, 4096)
						for {
							n, err := r.Body.Read(buf)
							if n > 0 {
								_, _ = w.Write(buf[:n])
								w.(http.Flusher).Flush()
							}
							if err != nil {
								return
							}
						}
					}))
					client, err := New(profile, net.Dialer{Timeout: 3 * time.Second})
					if err != nil {
						t.Fatal(err)
					}
					client.rootCAs = roots
					defer client.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					dialCtx, finishDial := context.WithCancel(ctx)
					conn, err := client.DialStream(dialCtx, "example.org:443")
					finishDial()
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					for i := 0; i < 10; i++ {
						message := strings.Repeat("a", i+1)
						if _, err := conn.Write([]byte(message)); err != nil {
							t.Fatal(err)
						}
						got := make([]byte, len(message))
						if _, err := io.ReadFull(conn, got); err != nil {
							t.Fatal(err)
						}
						if string(got) != message {
							t.Fatalf("got %q, want %q", got, message)
						}
					}
					if err := conn.CloseWrite(); err != nil {
						t.Fatal(err)
					}
					if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
						t.Fatalf("after half-close: %v", err)
					}
					other, err := client.DialStream(ctx, "example.org:8443")
					if err != nil {
						t.Fatal(err)
					}
					defer other.Close()
					if connections.Load() != 1 {
						t.Fatalf("different destinations opened %d proxy connections", connections.Load())
					}
					results := make(chan error, 4)
					for i := 0; i < 4; i++ {
						go func() {
							conn, err := client.DialStream(ctx, "example.org:443")
							if err != nil {
								results <- err
								return
							}
							defer conn.Close()
							if _, err = conn.Write([]byte("parallel")); err != nil {
								results <- err
								return
							}
							buf := make([]byte, 8)
							_, err = io.ReadFull(conn, buf)
							if err == nil && string(buf) != "parallel" {
								err = fmt.Errorf("parallel payload mismatch")
							}
							results <- err
						}()
					}
					for i := 0; i < 4; i++ {
						if err := <-results; err != nil {
							t.Fatal(err)
						}
					}
					_ = client.Close()
					if _, err := other.Read(make([]byte, 1)); err == nil {
						t.Fatal("client close left a stream open")
					}
				})
			}
		})
	}
}

func TestCloseCancelsPendingConnect(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			started := make(chan struct{})
			profile, roots, _ := testProxy(t, protocol, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				<-r.Context().Done()
			}))
			client, err := New(profile, net.Dialer{Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			client.rootCAs = roots
			defer client.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := client.DialStream(ctx, "example.org:443"); result <- err }()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			_ = client.Close()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("pending CONNECT succeeded after close")
				}
			case <-ctx.Done():
				t.Fatal("close did not cancel pending CONNECT")
			}
		})
	}
}

func TestTLSAndAuthFailures(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			profile, roots, _ := testProxy(t, protocol, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusProxyAuthRequired) }))
			profile.Naive.Password = "synthetic-secret"
			for _, trusted := range []bool{false, true} {
				client, err := New(profile, net.Dialer{Timeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				if trusted {
					client.rootCAs = roots
				}
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				_, err = client.DialStream(ctx, "example.org:443")
				cancel()
				_ = client.Close()
				if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
					t.Fatalf("unsafe or missing error: %v", err)
				}
				if trusted && !strings.Contains(err.Error(), "407") {
					t.Fatalf("auth response lost: %v", err)
				}
			}
		})
	}
}
