package winres

import (
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"unicode/utf16"
)

// Product strings written to the VERSIONINFO block of bimeron.exe.
const (
	ProductName      = "Bimeron Core"
	CompanyName      = "Bimeron contributors"
	LegalCopyright   = "Copyright (c) 2026 Bimeron contributors"
	OriginalFilename = "bimeron.exe"
	InternalName     = "bimeron"
)

// DevVersion is the version text of builds without a release version.
const DevVersion = "dev"

// Version is the release version as Windows sees it. Text is the full
// semantic version shown as the file and product version strings; Fixed is
// the numeric major.minor.patch.0 form of VS_FIXEDFILEINFO.
type Version struct {
	Text       string
	Fixed      [4]uint16
	Prerelease bool
}

var semver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// ParseVersion parses a semantic version without a "v" prefix, as passed to
// -X bimeron/core.Version. An empty version is a development build: the text
// is DevVersion and the numeric version is 0.0.0.0. The fourth numeric
// component is always 0, so prereleases of one version share a numeric
// version; the text keeps the full version.
func ParseVersion(text string) (Version, error) {
	if text == "" {
		return Version{Text: DevVersion, Prerelease: true}, nil
	}
	m := semver.FindStringSubmatch(text)
	if m == nil {
		return Version{}, fmt.Errorf("version %q is not a semantic version", text)
	}
	v := Version{Text: text, Prerelease: m[4] != ""}
	for i := range 3 {
		n, err := strconv.ParseUint(m[i+1], 10, 16)
		if err != nil {
			return Version{}, fmt.Errorf("version %q: component %s exceeds 65535", text, m[i+1])
		}
		v.Fixed[i] = uint16(n)
	}
	return v, nil
}

// VS_FIXEDFILEINFO constants.
const (
	fixedSignature  = 0xFEEF04BD
	fixedStrucVer   = 0x00010000
	fixedFlagsMask  = 0x3F
	fixedPrerelease = 0x2 // VS_FF_PRERELEASE
	fixedOSNTWin32  = 0x40004
	fixedTypeApp    = 0x1 // VFT_APP
	fixedInfoSize   = 52
)

// Translation of the single string table: U.S. English, Unicode (1200).
const (
	langEnglishUS   = 0x0409
	codepageUnicode = 0x04B0
	stringTableKey  = "040904B0"
)

// versionStrings returns the StringFileInfo entries in the order written.
func versionStrings(v Version) [][2]string {
	return [][2]string{
		{"CompanyName", CompanyName},
		{"FileDescription", ProductName},
		{"FileVersion", v.Text},
		{"InternalName", InternalName},
		{"LegalCopyright", LegalCopyright},
		{"OriginalFilename", OriginalFilename},
		{"ProductName", ProductName},
		{"ProductVersion", v.Text},
	}
}

// versionInfo encodes a VS_VERSIONINFO resource.
func versionInfo(v Version) []byte {
	fixed := make([]byte, fixedInfoSize)
	ms := uint32(v.Fixed[0])<<16 | uint32(v.Fixed[1])
	ls := uint32(v.Fixed[2])<<16 | uint32(v.Fixed[3])
	var flags uint32
	if v.Prerelease {
		flags = fixedPrerelease
	}
	for i, field := range []uint32{fixedSignature, fixedStrucVer, ms, ls, ms, ls, fixedFlagsMask, flags, fixedOSNTWin32, fixedTypeApp, 0, 0, 0} {
		binary.LittleEndian.PutUint32(fixed[4*i:], field)
	}
	var strs [][]byte
	for _, kv := range versionStrings(v) {
		value := utf16z(kv[1])
		strs = append(strs, versionNode(kv[0], value, uint16(len(value)/2), true))
	}
	table := versionNode(stringTableKey, nil, 0, true, strs...)
	translation := binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16(nil, langEnglishUS), codepageUnicode)
	return versionNode("VS_VERSION_INFO", fixed, fixedInfoSize, false,
		versionNode("StringFileInfo", nil, 0, true, table),
		versionNode("VarFileInfo", nil, 0, true, versionNode("Translation", translation, uint16(len(translation)), false)),
	)
}

// versionNode encodes one VERSIONINFO block: wLength, wValueLength, wType,
// the key, padding, the value and the children, each child 32-bit aligned.
// valueLength is in words for text values and in bytes for binary values.
func versionNode(key string, value []byte, valueLength uint16, text bool, children ...[]byte) []byte {
	b := make([]byte, 6, 64)
	binary.LittleEndian.PutUint16(b[2:], valueLength)
	if text {
		binary.LittleEndian.PutUint16(b[4:], 1)
	}
	b = pad4(append(b, utf16z(key)...))
	b = append(b, value...)
	for _, child := range children {
		b = append(pad4(b), child...)
	}
	binary.LittleEndian.PutUint16(b, uint16(len(b)))
	return b
}

func utf16z(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return append(b, 0, 0)
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// VersionInfo is a decoded VS_VERSIONINFO resource.
type VersionInfo struct {
	FileVersion    [4]uint16
	ProductVersion [4]uint16
	FileFlags      uint32
	FileType       uint32
	Translation    [2]uint16
	Strings        map[string]string
}

// ParseVersionInfo decodes a VS_VERSIONINFO resource with one string table.
func ParseVersionInfo(data []byte) (VersionInfo, error) {
	root, err := parseNode(data)
	if err != nil {
		return VersionInfo{}, err
	}
	if root.key != "VS_VERSION_INFO" || len(root.value) != fixedInfoSize {
		return VersionInfo{}, errors.New("VERSIONINFO: missing VS_FIXEDFILEINFO")
	}
	field := func(i int) uint32 { return binary.LittleEndian.Uint32(root.value[4*i:]) }
	if field(0) != fixedSignature {
		return VersionInfo{}, errors.New("VERSIONINFO: bad VS_FIXEDFILEINFO signature")
	}
	split := func(ms, ls uint32) [4]uint16 {
		return [4]uint16{uint16(ms >> 16), uint16(ms), uint16(ls >> 16), uint16(ls)}
	}
	info := VersionInfo{
		FileVersion:    split(field(2), field(3)),
		ProductVersion: split(field(4), field(5)),
		FileFlags:      field(7) & field(6),
		FileType:       field(9),
		Strings:        map[string]string{},
	}
	for _, child := range root.children {
		switch child.key {
		case "StringFileInfo":
			if len(child.children) != 1 {
				return VersionInfo{}, errors.New("VERSIONINFO: want exactly one string table")
			}
			for _, s := range child.children[0].children {
				value, err := decodeUTF16z(s.value)
				if err != nil {
					return VersionInfo{}, fmt.Errorf("VERSIONINFO: %s: %w", s.key, err)
				}
				info.Strings[s.key] = value
			}
		case "VarFileInfo":
			for _, v := range child.children {
				if v.key == "Translation" && len(v.value) >= 4 {
					info.Translation = [2]uint16{binary.LittleEndian.Uint16(v.value), binary.LittleEndian.Uint16(v.value[2:])}
				}
			}
		}
	}
	return info, nil
}

type node struct {
	key      string
	value    []byte
	children []node
}

func parseNode(data []byte) (node, error) {
	if len(data) < 6 {
		return node{}, errors.New("VERSIONINFO: truncated block")
	}
	length := int(binary.LittleEndian.Uint16(data))
	valueLength := int(binary.LittleEndian.Uint16(data[2:]))
	if length < 6 || length > len(data) {
		return node{}, errors.New("VERSIONINFO: block length out of range")
	}
	data = data[:length]
	off := 6
	var key []uint16
	for {
		if off+2 > len(data) {
			return node{}, errors.New("VERSIONINFO: unterminated key")
		}
		u := binary.LittleEndian.Uint16(data[off:])
		off += 2
		if u == 0 {
			break
		}
		key = append(key, u)
	}
	off = align4(off)
	if binary.LittleEndian.Uint16(data[4:]) == 1 {
		valueLength *= 2
	}
	if off+valueLength > len(data) {
		return node{}, errors.New("VERSIONINFO: value out of range")
	}
	n := node{key: string(utf16.Decode(key)), value: data[off : off+valueLength]}
	off = align4(off + valueLength)
	for off < len(data) {
		child, err := parseNode(data[off:])
		if err != nil {
			return node{}, err
		}
		n.children = append(n.children, child)
		off = align4(off + int(binary.LittleEndian.Uint16(data[off:])))
	}
	return n, nil
}

func align4(n int) int { return (n + 3) &^ 3 }

func decodeUTF16z(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", errors.New("odd UTF-16 length")
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			return string(utf16.Decode(u)), nil
		}
		u = append(u, c)
	}
	return "", errors.New("unterminated string")
}
