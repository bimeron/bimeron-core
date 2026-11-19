package control

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
	"unicode"

	"bimeron/internal/displaytext"
)

// A daemon error is returned to callers that print it, so it never carries
// control characters; a catalog code stays unchanged.
func TestExchangeErrorHasNoControlCharacters(t *testing.T) {
	r := string(displaytext.Replacement)
	for _, test := range []struct{ code, want string }{
		{"unknown_command", "unknown_command"},
		{"\x1b]0;title\x07bad\r\ncode", r + "]0;title" + r + "bad" + r + r + "code"},
	} {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			if _, err := bufio.NewReader(server).ReadBytes('\n'); err != nil {
				return
			}
			json.NewEncoder(server).Encode(Response{Version: Version, Error: test.code})
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := exchange(ctx, client, Request{Command: "status"})
		cancel()
		client.Close()
		if err == nil {
			t.Fatalf("%q: no error", test.code)
		}
		if strings.ContainsFunc(err.Error(), unicode.IsControl) || err.Error() != test.want {
			t.Errorf("%q: error %q, want %q", test.code, err.Error(), test.want)
		}
	}
}
