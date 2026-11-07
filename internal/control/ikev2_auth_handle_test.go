package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestIKEAuthActualHandle(t *testing.T) {
	for _, mode := range []string{"authorized", "absent", "denied", "unknown", "malformed", "oversize", "native"} {
		t.Run(mode, func(t *testing.T) {
			s, _, _ := authFixture(t)
			original := s.foregroundDispatch
			seen := false
			var authority *ikeAuth
			s.foregroundDispatch = func(ctx context.Context, r Request) Response {
				seen = true
				authority, _ = ctx.Value(ikeAuthorityKey{}).(*ikeAuth)
				if mode == "authorized" {
					if authority == nil || !s.beginIKEAuth(ctx, authBinding(), time.Minute, func([]byte, []byte) { t.Error("wire dispatched secrets") }) {
						t.Error("authority missing")
					}
				}
				return original(ctx, r)
			}
			if mode != "absent" {
				s.authorize = func(net.Conn) (func(), error) {
					if mode == "denied" {
						return nil, errors.New("denied")
					}
					return func() {}, nil
				}
			}
			line := `{"version":1,"id":"x","command":"hello","installation":"installation"}` + "\n"
			switch mode {
			case "unknown":
				line = `{"version":1,"command":"hello","username":"private-sentinel"}` + "\n"
			case "malformed":
				line = "{\n"
			case "oversize":
				line = strings.Repeat("x", maxRequest+1) + "\n"
			case "native":
				line = `{"version":1,"id":"x","command":"auth_reply","installation":"installation","instance":"instance","session":"session","challenge_id":"x","answers":["private-sentinel"]}` + "\n"
			}
			server, client := net.Pipe()
			defer client.Close()
			client.SetDeadline(time.Now().Add(time.Second))
			done := make(chan struct{})
			go func() { defer close(done); s.handle(context.Background(), server) }()
			client.Write([]byte(line))
			data, _ := io.ReadAll(client)
			<-done
			expected := mode == "authorized" || mode == "absent" || mode == "native"
			if seen != expected {
				t.Fatal("unexpected decoder dispatch")
			}
			if mode == "absent" && authority != nil {
				t.Fatal("unauthorized authority")
			}
			if mode == "authorized" {
				if authority.live || authority.consume != nil || s.ikePending != nil || s.ikeOwner.Err() != nil {
					t.Fatal("exchange retirement")
				}
				var r Response
				if json.Unmarshal(data, &r) != nil || r.Capabilities == nil {
					t.Fatal("hello")
				}
				c := r.Capabilities.IKEv2
				if c.AuthSubmission || c.AuthAttemptOnly || c.AuthWindowsPersistence || c.AuthCertificateSelection || c.AuthSmartCardInteraction {
					t.Fatal("advertised native auth")
				}
			}
			if mode == "native" {
				var r Response
				json.Unmarshal(data, &r)
				if r.Error == "" {
					t.Fatal("native answer accepted")
				}
			}
			if strings.Contains(string(data), "private-sentinel") {
				t.Fatal("wire leak")
			}
		})
	}
}
