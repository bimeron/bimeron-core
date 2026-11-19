package core

import (
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// maxAliasLabel bounds the label part of a WireGuard adapter alias in
// runes; maxAliasUTF16 bounds the whole alias in UTF-16 code units, below
// Wintun's 128-unit adapter name limit.
const (
	maxAliasLabel = 48
	maxAliasUTF16 = 100
)

// aliasWildcards are PowerShell wildcard characters: the network scripts
// look adapters up with Get-NetAdapter -Name, which would treat them as a
// pattern and could match a foreign adapter.
const aliasWildcards = "*?[]`"

// wireGuardAdapterAlias returns the Windows adapter alias of a WireGuard
// profile, "Bimeron WG — Office" or "Bimeron AWG — Office". The generated
// alias is separate from the portable [Interface] Name, which keeps its
// ASCII rule. Whitespace is collapsed, control, format (including bidi)
// and wildcard characters are dropped or replaced, and the length is
// bounded in runes and UTF-16 units.
func wireGuardAdapterAlias(protocol, label string) string {
	label = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case r == utf8.RuneError, unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			return -1
		case strings.ContainsRune(aliasWildcards, r):
			return '_'
		}
		return r
	}, label)
	label = strings.Join(strings.Fields(label), " ")
	runes := []rune(label)
	if len(runes) > maxAliasLabel {
		runes = runes[:maxAliasLabel]
	}
	prefix := "Bimeron " + protocol
	for len(runes) > 0 && len(utf16.Encode([]rune(prefix+" — "+string(runes)))) > maxAliasUTF16 {
		runes = runes[:len(runes)-1]
	}
	label = strings.TrimSpace(string(runes))
	if label == "" {
		return prefix
	}
	return prefix + " — " + label
}

// validAdapterAlias accepts only aliases that wireGuardAdapterAlias can
// produce.
func validAdapterAlias(alias string) bool {
	if !strings.HasPrefix(alias, "Bimeron ") || !utf8.ValidString(alias) || len(utf16.Encode([]rune(alias))) > maxAliasUTF16 {
		return false
	}
	for _, r := range alias {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || strings.ContainsRune(aliasWildcards, r) || (unicode.IsSpace(r) && r != ' ') {
			return false
		}
	}
	return !strings.Contains(alias, "  ") && strings.TrimSpace(alias) == alias
}
