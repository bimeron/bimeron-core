// Package wgconf parses, validates and edits WireGuard and AmneziaWG
// configuration text in the wg-quick format. It never reads files, resolves
// names or touches the network. Problems never contain values.
package wgconf

import (
	"slices"
	"strings"
	"unicode/utf8"

	"bimeron/internal/problem"
)

// MaxSize bounds WireGuard text, matching profile and key file limits.
const MaxSize = 64 * 1024

// bom is the UTF-8 byte order mark, retained byte for byte.
var bom = string(rune(0xFEFF))

// DocumentName is the problem Document marker for WireGuard text.
const DocumentName = "wireguard"

// Section names.
const (
	Interface = "Interface"
	Peer      = "Peer"
)

// line is one physical line with its terminator.
type line struct {
	raw string
	// section is the index into Document.sections, or -1 before any header.
	section int
	// header is true for a section header line.
	header bool
	// key is the canonical key, or the trimmed key text when unknown.
	key   string
	value string
	// known reports that key is a recognized option of its section.
	known bool
	// malformed marks a non-blank line that is neither a header nor key=value.
	malformed bool
}

type section struct {
	// name is the canonical section name or the trimmed header text.
	name  string
	known bool
	line  int // zero-based header line index
}

// Document is a byte-preserving WireGuard draft. Bytes returns the original
// text until an edit changes it. It is not safe for concurrent use.
type Document struct {
	bom      string
	lines    []line
	sections []section
}

// tooLarge and notUTF8 are reported before any parsing.
func checkText(text string) error {
	if len(text) > MaxSize {
		return problem.New("file_too_large", "WireGuard configuration exceeds size limit").Arg("limit", "64 KiB").InDocument(DocumentName)
	}
	if !utf8.ValidString(text) {
		return problem.New("file_not_utf8", "WireGuard configuration must be UTF-8").InDocument(DocumentName)
	}
	return nil
}

// ParseDocument splits text into lines. It fails only for size and encoding.
func ParseDocument(text string) (*Document, error) {
	if err := checkText(text); err != nil {
		return nil, err
	}
	d := &Document{}
	if strings.HasPrefix(text, bom) {
		d.bom = bom
		text = text[len(d.bom):]
	}
	for len(text) > 0 {
		end := strings.IndexByte(text, '\n')
		if end < 0 {
			end = len(text) - 1
		}
		d.lines = append(d.lines, line{raw: text[:end+1]})
		text = text[end+1:]
	}
	d.reindex()
	return d, nil
}

// content strips the terminator and an end-of-line comment.
func content(raw string) string {
	raw = strings.TrimRight(raw, "\r\n")
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(raw)
}

func (d *Document) reindex() {
	d.sections = d.sections[:0]
	current := -1
	for i := range d.lines {
		l := &d.lines[i]
		raw := l.raw
		*l = line{raw: raw, section: current}
		text := content(raw)
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "[") {
			if !strings.HasSuffix(text, "]") {
				l.malformed = true
				continue
			}
			name := strings.TrimSpace(text[1 : len(text)-1])
			s := section{name: name, line: i}
			if canonical, ok := canonicalSection(name); ok {
				s.name, s.known = canonical, true
			}
			d.sections = append(d.sections, s)
			current = len(d.sections) - 1
			l.section, l.header = current, true
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" || current < 0 {
			l.malformed = true
			continue
		}
		l.value = strings.TrimSpace(value)
		l.key = key
		if d.sections[current].known {
			if canonical, ok := canonicalKey(d.sections[current].name, key); ok {
				l.key, l.known = canonical, true
			}
		}
	}
}

// Bytes returns a detached copy of the text.
func (d *Document) Bytes() []byte { return []byte(d.String()) }

// String returns the text.
func (d *Document) String() string {
	var b strings.Builder
	b.WriteString(d.bom)
	for _, l := range d.lines {
		b.WriteString(l.raw)
	}
	return b.String()
}

func canonicalSection(name string) (string, bool) {
	for _, s := range []string{Interface, Peer} {
		if strings.EqualFold(s, name) {
			return s, true
		}
	}
	return "", false
}

// canonicalKey matches keys case-insensitively, as wg-quick does.
func canonicalKey(section, key string) (string, bool) {
	for _, k := range sectionKeys(section) {
		if strings.EqualFold(k, key) {
			return k, true
		}
	}
	return "", false
}

func sectionKeys(section string) []string {
	if section == Interface {
		return interfaceKeys
	}
	return peerKeys
}

var interfaceKeys = append([]string{"PrivateKey", "Address", "DNS", "MTU", "ListenPort"}, AWGKeys...)
var peerKeys = []string{"PublicKey", "PresharedKey", "Endpoint", "AllowedIPs", "PersistentKeepalive"}

// AWGKeys lists the AmneziaWG [Interface] options of all versions.
var AWGKeys = []string{
	"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
	"I1", "I2", "I3", "I4", "I5",
	"HeaderProtectionKey", "ContentPaddingAddition",
	"RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts",
	"RandomTrailers", "DisableCookies",
}

// listKeys may repeat; their values are joined with ", ".
var listKeys = map[string]bool{"Address": true, "DNS": true, "AllowedIPs": true}

// SecretFields are the "Section/Key" fields holding secrets.
var SecretFields = []string{"Interface/PrivateKey", "Peer/PresharedKey", "Interface/HeaderProtectionKey"}

// structureError reports why fields cannot be presented unambiguously.
func (d *Document) structureError() error {
	counts := map[string]int{}
	for _, s := range d.sections {
		if s.known {
			counts[s.name]++
		}
	}
	if counts[Interface] > 1 {
		return problem.New("section_duplicate", "duplicate [Interface] section").In(Interface).InDocument(DocumentName)
	}
	if counts[Peer] > 1 {
		return problem.New("wireguard_peer_count", "WireGuard profiles support exactly one [Peer]").In(Peer).ArgInt("count", counts[Peer]).InDocument(DocumentName)
	}
	seen := map[string]bool{}
	for i, l := range d.lines {
		if l.malformed {
			return problem.New("syntax_invalid", "invalid WireGuard configuration line").AtLine(i + 1).InDocument(DocumentName)
		}
		if !l.known || listKeys[l.key] {
			continue
		}
		id := d.sections[l.section].name + "/" + l.key
		if seen[id] {
			return problem.New("option_duplicate", "duplicate WireGuard option").In(d.sections[l.section].name).At(l.key).AtLine(i + 1).InDocument(DocumentName)
		}
		seen[id] = true
	}
	return nil
}

// Fields returns "Section/Key" to decoded values of recognized options.
// It fails when the structure is ambiguous; callers then use raw editing.
func (d *Document) Fields() (map[string]string, error) {
	if err := d.structureError(); err != nil {
		return nil, err
	}
	fields := map[string]string{}
	for _, l := range d.lines {
		if !l.known || l.value == "" {
			continue
		}
		id := d.sections[l.section].name + "/" + l.key
		if old, ok := fields[id]; ok && listKeys[l.key] {
			fields[id] = old + ", " + l.value
			continue
		}
		fields[id] = l.value
	}
	return fields, nil
}

// lineEnding returns the document's line terminator style.
func (d *Document) lineEnding() string {
	for _, l := range d.lines {
		if strings.HasSuffix(l.raw, "\r\n") {
			return "\r\n"
		}
	}
	return "\n"
}

// SetField replaces, adds or (for an empty value) removes an option while
// keeping all other bytes. Sections created from scratch are ordered
// [Interface] then [Peer].
func (d *Document) SetField(sectionName, key, value string) error {
	fail := func(code, message string) error {
		return problem.New(code, message).In(sectionName).At(key).InDocument(DocumentName)
	}
	if sectionName != Interface && sectionName != Peer {
		return problem.New("section_unknown", "WireGuard section must be Interface or Peer").InDocument(DocumentName)
	}
	canonical, ok := canonicalKey(sectionName, key)
	if !ok || canonical != key {
		return fail("option_unknown", "unknown WireGuard option")
	}
	if value != strings.TrimSpace(value) || strings.ContainsAny(value, "#\r\n") {
		return fail("value_has_invalid_characters", "WireGuard values cannot contain #, line breaks or outer spaces")
	}
	target := -1
	for i, s := range d.sections {
		if s.known && s.name == sectionName {
			if target >= 0 {
				return problem.New("section_ambiguous", "duplicate WireGuard section").In(sectionName).InDocument(DocumentName)
			}
			target = i
		}
	}
	var matches []int
	if target >= 0 {
		for i, l := range d.lines {
			if l.section == target && l.known && l.key == key {
				matches = append(matches, i)
			}
		}
		if len(matches) > 1 && !listKeys[key] {
			return fail("option_duplicate", "duplicate WireGuard option")
		}
	}
	eol := d.lineEnding()
	if value == "" {
		d.remove(matches)
		return nil
	}
	if len(matches) > 0 {
		first := matches[0]
		d.lines[first].raw = replaceValue(d.lines[first].raw, value)
		d.remove(matches[1:])
		return nil
	}
	newLine := key + " = " + value + eol
	if target < 0 {
		d.addSection(sectionName, newLine, eol)
		return nil
	}
	// Insert after the last non-blank line of the section.
	at := d.sections[target].line
	for i := at + 1; i < len(d.lines) && d.lines[i].section == target && !d.lines[i].header; i++ {
		if strings.TrimSpace(d.lines[i].raw) != "" {
			at = i
		}
	}
	d.terminate(at, eol)
	d.insert(at+1, newLine)
	return nil
}

// replaceValue keeps the key spelling, spacing and terminator of raw.
func replaceValue(raw, value string) string {
	terminator := ""
	switch {
	case strings.HasSuffix(raw, "\r\n"):
		terminator = "\r\n"
	case strings.HasSuffix(raw, "\n"):
		terminator = "\n"
	}
	body := strings.TrimSuffix(raw, terminator)
	comment := ""
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body, comment = body[:i], body[i:]
	}
	eq := strings.IndexByte(body, '=')
	rest := body[eq+1:]
	lead := rest[:len(rest)-len(strings.TrimLeft(rest, " \t"))]
	trail := ""
	if comment != "" {
		trail = rest[len(strings.TrimRight(rest, " \t")):]
		if trail == "" {
			trail = " "
		}
	}
	return body[:eq+1] + lead + value + trail + comment + terminator
}

// terminate supplies a missing terminator on line i.
func (d *Document) terminate(i int, eol string) {
	if i >= 0 && i < len(d.lines) && !strings.HasSuffix(d.lines[i].raw, "\n") {
		d.lines[i].raw += eol
	}
}

// insert places text, which may hold several lines, before line at.
func (d *Document) insert(at int, text string) {
	var added []line
	for len(text) > 0 {
		end := strings.IndexByte(text, '\n')
		if end < 0 {
			end = len(text) - 1
		}
		added = append(added, line{raw: text[:end+1]})
		text = text[end+1:]
	}
	d.lines = append(d.lines[:at], append(added, d.lines[at:]...)...)
	d.reindex()
}

func (d *Document) remove(indexes []int) {
	if len(indexes) == 0 {
		return
	}
	drop := map[int]bool{}
	for _, i := range indexes {
		drop[i] = true
	}
	kept := d.lines[:0]
	for i, l := range d.lines {
		if !drop[i] {
			kept = append(kept, l)
		}
	}
	d.lines = kept
	d.reindex()
}

// addSection creates a section; [Interface] goes before an existing [Peer].
func (d *Document) addSection(name, first, eol string) {
	block := "[" + name + "]" + eol + first
	if name == Interface {
		for _, s := range d.sections {
			if s.known && s.name == Peer {
				at := s.line
				d.insert(at, block+eol)
				return
			}
		}
	}
	last := len(d.lines) - 1
	d.terminate(last, eol)
	if last >= 0 && strings.TrimSpace(d.lines[last].raw) != "" {
		block = eol + block
	}
	d.insert(len(d.lines), block)
}

// AccessOption reports a WireGuard option accepted directly in a Bimeron
// [AccessKey] section. PublicKey is shared with VLESS and handled there.
func AccessOption(key string) bool {
	return key != "PublicKey" && (slices.Contains(interfaceKeys, key) || slices.Contains(peerKeys, key))
}

// PeerOption reports a [Peer] option.
func PeerOption(key string) bool { return slices.Contains(peerKeys, key) }
