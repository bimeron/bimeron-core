// Package socksauth implements the server side of SOCKS5 method selection
// and optional RFC 1929 username/password authentication for the local
// listener. Credentials never appear in errors, problems or logs.
package socksauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"unicode/utf8"

	"bimeron/internal/problem"
)

// MaxLength is the RFC 1929 limit for a username or password, in bytes.
const MaxLength = 255

const (
	methodNone     = 0x00
	methodPassword = 0x02
	methodRefused  = 0xff
	authVersion    = 0x01
)

// Validate checks optional listener credentials: both empty, or both set
// with 1..MaxLength bytes of UTF-8 without control characters. Problems name
// the field only, never the value.
func Validate(username, password string) error {
	if username == "" && password == "" {
		return nil
	}
	if username == "" {
		return problem.New("listen_auth_incomplete", "[Interface] ListenUsername and ListenPassword must be set together").In("Interface").At("ListenUsername").Also("ListenPassword")
	}
	if password == "" {
		return problem.New("listen_auth_incomplete", "[Interface] ListenUsername and ListenPassword must be set together").In("Interface").At("ListenPassword").Also("ListenUsername")
	}
	for _, f := range []struct{ field, value string }{{"ListenUsername", username}, {"ListenPassword", password}} {
		if !validValue(f.value) {
			return problem.New("listen_auth_invalid", "[Interface] "+f.field+" must be 1-255 bytes without control characters").In("Interface").At(f.field).Arg("max", "255")
		}
	}
	return nil
}

func validValue(s string) bool {
	if len(s) == 0 || len(s) > MaxLength || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f {
			return false
		}
	}
	return true
}

// Credentials holds digests of the expected username and password.
// A nil *Credentials accepts only the "no authentication" method.
type Credentials struct {
	username, password [sha256.Size]byte
}

// New returns nil when both values are empty. Call Validate first.
func New(username, password string) *Credentials {
	if username == "" && password == "" {
		return nil
	}
	return &Credentials{sha256.Sum256([]byte(username)), sha256.Sum256([]byte(password))}
}

// match compares fixed-size digests in constant time, so neither the
// position of the first difference nor the lengths are observable.
func (c *Credentials) match(username, password []byte) bool {
	u, p := sha256.Sum256(username), sha256.Sum256(password)
	return subtle.ConstantTimeCompare(u[:], c.username[:])&subtle.ConstantTimeCompare(p[:], c.password[:]) == 1
}

// Negotiate reads the complete client greeting, selects a method and, with
// credentials, runs RFC 1929. It reports whether the client may continue with
// a request. On failure it has already written the refusal the protocol
// defines, if any.
func Negotiate(rw io.ReadWriter, c *Credentials) bool {
	var h [2]byte
	if _, err := io.ReadFull(rw, h[:]); err != nil || h[0] != 5 || h[1] == 0 {
		return false
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(rw, methods); err != nil {
		return false
	}
	want := byte(methodNone)
	if c != nil {
		want = methodPassword
	}
	offered := false
	for _, m := range methods {
		if m == want {
			offered = true
		}
	}
	if !offered {
		_, _ = rw.Write([]byte{5, methodRefused})
		return false
	}
	if _, err := rw.Write([]byte{5, want}); err != nil {
		return false
	}
	if c == nil {
		return true
	}
	username, ok := readField(rw, true)
	if !ok {
		return false
	}
	password, ok := readField(rw, false)
	if !ok {
		return false
	}
	if !c.match(username, password) {
		_, _ = rw.Write([]byte{authVersion, 1})
		return false
	}
	_, err := rw.Write([]byte{authVersion, 0})
	return err == nil
}

// readField reads one length-prefixed field; the username is preceded by the
// sub-negotiation version. Zero lengths are read and later fail the match.
func readField(r io.Reader, first bool) ([]byte, bool) {
	if first {
		var version [1]byte
		if _, err := io.ReadFull(r, version[:]); err != nil || version[0] != authVersion {
			return nil, false
		}
	}
	var length [1]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, false
	}
	b := make([]byte, int(length[0]))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, false
	}
	return b, true
}
