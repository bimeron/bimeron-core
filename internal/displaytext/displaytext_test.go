package displaytext

import (
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
			if again := clean(out); again != out {
				t.Fatalf("%s is not idempotent: %q then %q", name, out, again)
			}
			if name == "Text" && !strings.Contains(s, "\r") && strings.Count(out, "\n") < strings.Count(s, "\n") {
				t.Fatalf("Text(%q) = %q drops line feeds", s, out)
			}
		}
	})
}
