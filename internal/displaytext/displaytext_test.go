package displaytext

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// u spells a code point without putting it into the source text.
func u(r rune) string { return string(r) }

var fffd = u(Replacement)

func TestText(t *testing.T) {
	for _, test := range []struct{ in, want string }{
		{"Password", "Password"},
		{"Пароль: код", "Пароль: код"},
		{"Verification code" + u(0x1F511), "Verification code" + u(0x1F511)},
		{"line one\nline two\tvalue", "line one\nline two\tvalue"},
		{"a\r\nb", "a\nb"},
		{"a\rb", "a\nb"},
		{"a\r\r\nb", "a\n\nb"},
		{"a" + u(0x2028) + "b" + u(0x2029) + "c", "a\nb\nc"},
		{"\x1b]0;title\x07Password", fffd + "]0;title" + fffd + "Password"},
		{"\x1b]52;c;Zm9v\x1b\\Password", fffd + "]52;c;Zm9v" + fffd + "\\Password"},
		{"\x1b[2J\x1b[1;1HBimeron", fffd + "[2J" + fffd + "[1;1HBimeron"},
		{"a\bb\x00c\x7fd", "a" + fffd + "b" + fffd + "c" + fffd + "d"},
		{"x" + u(0x9b) + "31m" + u(0x85) + u(0x9d), "x" + fffd + "31m" + fffd + fffd},
		{u(0x202E) + "drowssaP", fffd + "drowssaP"},
		{u(0x2066) + "a" + u(0x2069) + u(0x200F) + u(0x200E) + u(0x061C) + u(0x202A), fffd + "a" + fffd + fffd + fffd + fffd + fffd},
		{"bad\xffutf8\xc3", "bad" + fffd + "utf8" + fffd},
		{fffd, fffd},
		{"", ""},
	} {
		if got := Text(test.in); got != test.want {
			t.Errorf("Text(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

func TestLine(t *testing.T) {
	for _, test := range []struct{ in, want string }{
		{"Main profile", "Main profile"},
		{"tcp.example", "tcp.example"},
		{"a\nb\tc\r\nd", "a" + fffd + "b" + fffd + "c" + fffd + fffd + "d"},
		{"a" + u(0x2028) + "b", "a" + fffd + "b"},
		{"\x1b[31mred", fffd + "[31mred"},
		{u(0x202E) + "x", fffd + "x"},
	} {
		if got := Line(test.in); got != test.want {
			t.Errorf("Line(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

func FuzzText(f *testing.F) {
	for _, seed := range []string{"Password", "a\r\nb", "\x1b]0;x\x07", u(0x202E) + "x", "\xff", u(0x2028)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for name, clean := range map[string]func(string) string{"Text": Text, "Line": Line} {
			out := clean(s)
			if !utf8.ValidString(out) {
				t.Fatalf("%s(%q) = %q: invalid UTF-8", name, s, out)
			}
			for _, r := range out {
				if r == '\n' || r == '\t' {
					if name == "Line" {
						t.Fatalf("Line(%q) = %q keeps %q", s, out, r)
					}
					continue
				}
				if unsafeRune(r) || r == lineSeparator || r == paragraphSeparator {
					t.Fatalf("%s(%q) = %q keeps %U", name, s, out, r)
				}
			}
			if keeps(s, name == "Text") && out != s {
				t.Fatalf("%s(%q) = %q changes safe text", name, s, out)
			}
			if again := clean(out); again != out {
				t.Fatalf("%s is not idempotent: %q then %q", name, out, again)
			}
			if name == "Text" && !strings.Contains(s, "\r") && strings.Count(out, "\n") < strings.Count(s, "\n") {
				t.Fatalf("Text(%q) = %q drops line feeds", s, out)
			}
		}
	})
}

func TestEscapeJSON(t *testing.T) {
	in, err := json.Marshal(map[string]string{"version": "v1\x1b]0;t\x07" + u(0x9b) + "2J" + u(0x7f) + u(0x202E) + u(0x2028) + "Пароль"})
	if err != nil {
		t.Fatal(err)
	}
	out := EscapeJSON(in)
	for _, r := range string(out) {
		if unsafeRune(r) || r == lineSeparator || r == paragraphSeparator {
			t.Fatalf("EscapeJSON kept %U: %s", r, out)
		}
	}
	var back, orig map[string]string
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(in, &orig)
	if back["version"] != orig["version"] {
		t.Fatalf("EscapeJSON changed the value: %q, want %q", back["version"], orig["version"])
	}
	if plain := []byte(`{"version":"v1.2.3"}`); &EscapeJSON(plain)[0] != &plain[0] {
		t.Fatal("EscapeJSON copied safe JSON")
	}
}

// keeps reports whether multiline (Text) or single-line (Line) cleaning must
// leave s unchanged.
func keeps(s string, multiline bool) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if (r == '\n' || r == '\t') && multiline {
			continue
		}
		if r == '\n' || r == '\t' || r == '\r' || r == lineSeparator || r == paragraphSeparator || unsafeRune(r) {
			return false
		}
	}
	return true
}

func FuzzEscapeJSON(f *testing.F) {
	for _, seed := range []string{"v1.2.3", "\x1b[2J", u(0x9b), u(0x202E) + "x", "\xff", u(0x2029)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		in, err := json.Marshal(s)
		if err != nil {
			t.Skip()
		}
		out := EscapeJSON(in)
		var back string
		if err := json.Unmarshal(out, &back); err != nil {
			t.Fatalf("EscapeJSON(%s) = %s: %v", in, out, err)
		}
		var orig string
		json.Unmarshal(in, &orig)
		if back != orig {
			t.Fatalf("EscapeJSON(%s) decodes to %q, want %q", in, back, orig)
		}
		for _, r := range string(out) {
			if unsafeRune(r) || r == lineSeparator || r == paragraphSeparator {
				t.Fatalf("EscapeJSON(%s) = %s keeps %U", in, out, r)
			}
		}
	})
}
