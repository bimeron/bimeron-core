package socksauth

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"bimeron/internal/problem"
)

type exchange struct {
	*bytes.Reader
	out bytes.Buffer
}

func (e *exchange) Write(p []byte) (int, error) { return e.out.Write(p) }

func run(input []byte, c *Credentials) (bool, []byte) {
	e := &exchange{Reader: bytes.NewReader(input)}
	ok := Negotiate(e, c)
	return ok, e.out.Bytes()
}

func authRequest(username, password string) []byte {
	b := []byte{1, byte(len(username))}
	b = append(b, username...)
	b = append(b, byte(len(password)))
	return append(b, password...)
}

func TestNegotiateWithoutCredentials(t *testing.T) {
	if ok, out := run([]byte{5, 1, 0}, nil); !ok || !bytes.Equal(out, []byte{5, 0}) {
		t.Fatalf("anonymous greeting: %v %x", ok, out)
	}
	if ok, out := run([]byte{5, 1, 2}, nil); ok || !bytes.Equal(out, []byte{5, 0xff}) {
		t.Fatalf("password-only client without configured credentials: %v %x", ok, out)
	}
	if ok, out := run([]byte{4, 1, 0}, nil); ok || len(out) != 0 {
		t.Fatalf("wrong version: %v %x", ok, out)
	}
	if ok, _ := run([]byte{5, 0}, nil); ok {
		t.Fatal("empty method list accepted")
	}
}

func TestNegotiateWithCredentials(t *testing.T) {
	c := New("alice", "s3cret")
	greeting := []byte{5, 2, 0, 2}
	if ok, out := run(append(greeting, authRequest("alice", "s3cret")...), c); !ok || !bytes.Equal(out, []byte{5, 2, 1, 0}) {
		t.Fatalf("valid credentials: %v %x", ok, out)
	}
	for _, bad := range [][2]string{{"alice", "wrong"}, {"bob", "s3cret"}, {"alice", "s3cret!"}, {"", ""}, {"alic", "es3cret"}} {
		if ok, out := run(append(greeting, authRequest(bad[0], bad[1])...), c); ok || !bytes.Equal(out, []byte{5, 2, 1, 1}) {
			t.Fatalf("credentials %q accepted or wrong reply: %v %x", bad, ok, out)
		}
	}
	if ok, out := run([]byte{5, 1, 0}, c); ok || !bytes.Equal(out, []byte{5, 0xff}) {
		t.Fatalf("anonymous client with configured credentials: %v %x", ok, out)
	}
	if ok, out := run(append([]byte{5, 1, 2, 5}, authRequest("alice", "s3cret")[1:]...), c); ok || !bytes.Equal(out, []byte{5, 2}) {
		t.Fatalf("wrong sub-negotiation version: %v %x", ok, out)
	}
	if ok, _ := run([]byte{5, 1, 2, 1, 5, 'a'}, c); ok {
		t.Fatal("truncated username accepted")
	}
}

func TestValidate(t *testing.T) {
	long := strings.Repeat("a", MaxLength)
	for _, valid := range [][2]string{{"", ""}, {"u", "p"}, {long, long}, {"пользователь", "pass word"}} {
		if err := Validate(valid[0], valid[1]); err != nil {
			t.Fatalf("%q: %v", valid, err)
		}
	}
	for _, c := range []struct {
		username, password, code, field string
	}{
		{"user", "", "listen_auth_incomplete", "ListenPassword"},
		{"", "secret-value", "listen_auth_incomplete", "ListenUsername"},
		{long + "a", "p", "listen_auth_invalid", "ListenUsername"},
		{"u", long + "a", "listen_auth_invalid", "ListenPassword"},
		{"u\x01", "p", "listen_auth_invalid", "ListenUsername"},
		{"u", "secret\x7f", "listen_auth_invalid", "ListenPassword"},
		{"u", "secret\u0085", "listen_auth_invalid", "ListenPassword"},
		{"u", "secret\xff", "listen_auth_invalid", "ListenPassword"},
	} {
		err := Validate(c.username, c.password)
		var p *problem.Error
		if !errors.As(err, &p) || p.Code != c.code || p.Section != "Interface" || p.Field != c.field {
			t.Fatalf("%q/%q: %#v", c.username, c.password, err)
		}
		if strings.Contains(err.Error(), "secret") || p.Value != "" {
			t.Fatal("problem carries the value")
		}
	}
}

func FuzzNegotiate(f *testing.F) {
	f.Add([]byte{5, 1, 0}, false)
	f.Add(append([]byte{5, 2, 0, 2}, authRequest("alice", "s3cret")...), true)
	f.Add(append([]byte{5, 1, 2}, authRequest("alice", "wrong")...), true)
	f.Add([]byte{5, 255}, true)
	f.Add([]byte{5, 1, 2, 1, 255}, true)
	c := New("alice", "s3cret")
	f.Fuzz(func(t *testing.T, input []byte, withCredentials bool) {
		var creds *Credentials
		if withCredentials {
			creds = c
		}
		ok, out := run(input, creds)
		// Every reply is one of the sequences RFC 1928/1929 allow here.
		allowed := false
		for _, reply := range [][]byte{{}, {5, 0xff}, {5, 0}, {5, 2}, {5, 2, 1, 0}, {5, 2, 1, 1}} {
			if bytes.Equal(out, reply) {
				allowed = true
			}
		}
		if !allowed {
			t.Fatalf("unexpected reply %x", out)
		}
		if !ok {
			return
		}
		if len(input) < 2 || input[0] != 5 {
			t.Fatalf("accepted invalid SOCKS greeting: %x", input)
		}
		greeting := 2 + int(input[1])
		if greeting > len(input) || len(out) < 2 || !bytes.Contains(input[2:greeting], out[1:2]) {
			t.Fatalf("selected an unoffered method: input %x, reply %x", input, out)
		}
		if !withCredentials {
			if !bytes.Equal(out, []byte{5, 0}) {
				t.Fatalf("accepted with reply %x", out)
			}
			return
		}
		// Success requires the exact credentials right after the greeting.
		if !bytes.Equal(out, []byte{5, 2, 1, 0}) || !bytes.HasPrefix(input[greeting:], authRequest("alice", "s3cret")) {
			t.Fatalf("accepted without credentials: %x", input)
		}
	})
}
