// Package displaytext prepares text that comes from outside Core, such as SSH
// server prompts or daemon responses, for display in a terminal or a GUI.
//
// Control characters can move the cursor, rewrite earlier output or change a
// terminal's title, and bidirectional formatting characters can reorder the
// displayed text. Both are replaced with U+FFFD so that a change stays
// visible. Invalid UTF-8 is replaced the same way.
package displaytext

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Replacement (U+FFFD) stands in for every removed character.
const Replacement rune = utf8.RuneError

// Unicode line and paragraph separators.
const (
	lineSeparator      rune = 0x2028
	paragraphSeparator rune = 0x2029
)

// Text keeps line breaks and tabs. CR LF, a lone CR and the Unicode line and
// paragraph separators become LF. Every other C0 control, DEL, every C1
// control and every bidirectional formatting character becomes U+FFFD.
func Text(s string) string { return clean(s, true) }

// Line is Text for single-line output: line breaks, line separators and tabs
// become U+FFFD as well.
func Line(s string) string { return clean(s, false) }

func clean(s string, multiline bool) string {
	if safe(s, multiline) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size == 1:
			r = Replacement
		case r == '\r' && multiline:
			if i < len(s) && s[i] == '\n' {
				i++
			}
			r = '\n'
		case r == lineSeparator || r == paragraphSeparator:
			r = Replacement
			if multiline {
				r = '\n'
			}
		case r == '\n' || r == '\t':
			if !multiline {
				r = Replacement
			}
		case unsafeRune(r):
			r = Replacement
		}
		b.WriteRune(r)
	}
	return b.String()
}

// safe reports whether clean would return s unchanged.
func safe(s string, multiline bool) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size == 1:
			return false
		case r == '\n' || r == '\t':
			if !multiline {
				return false
			}
		case r == '\r' || r == lineSeparator || r == paragraphSeparator || unsafeRune(r):
			return false
		}
	}
	return true
}

// unsafeRune reports C0 and C1 controls, DEL and the bidirectional formatting
// characters: ALM (U+061C), LRM (U+200E), RLM (U+200F), the embeddings and
// overrides U+202A to U+202E, and the isolates U+2066 to U+2069.
func unsafeRune(r rune) bool {
	switch {
	case unicode.IsControl(r):
		return true
	case r == 0x061C, r == 0x200E, r == 0x200F:
		return true
	case r >= 0x202A && r <= 0x202E:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}
