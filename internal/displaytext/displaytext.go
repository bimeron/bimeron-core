// Package displaytext prepares text that comes from outside Core, such as SSH
// server prompts or daemon responses, for display in a terminal or a GUI.
//
// Control characters can move the cursor, rewrite earlier output or change a
// terminal's title, and bidirectional formatting characters can reorder the
// displayed text. Both are replaced with U+FFFD so that a change stays
// visible. Invalid UTF-8 is replaced the same way.
package displaytext

import (
	"fmt"
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

// EscapeJSON writes every control character, bidirectional formatting
// character and line or paragraph separator in encoded JSON as a \u escape.
// encoding/json already escapes C0 controls and the separators, but writes
// DEL, C1 controls and bidirectional formatting characters as they are. Such
// characters only occur inside JSON strings, so the result is equivalent JSON.
func EscapeJSON(b []byte) []byte {
	var out []byte
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if !unsafeRune(r) && r != lineSeparator && r != paragraphSeparator {
			if out != nil {
				out = append(out, b[i:i+size]...)
			}
			i += size
			continue
		}
		if out == nil {
			out = append(make([]byte, 0, len(b)+16), b[:i]...)
		}
		out = fmt.Appendf(out, `\u%04x`, r)
		i += size
	}
	if out == nil {
		return b
	}
	return out
}

// unsafeRune reports C0 and C1 controls, DEL and the Unicode Bidi_Control
// characters: ALM, LRM, RLM, the embeddings and overrides U+202A to U+202E,
// and the isolates U+2066 to U+2069.
func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r)
}
