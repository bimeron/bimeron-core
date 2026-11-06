// Package applemanifest prepares and verifies the separate Apple update contract.
// It contains no shipping trust defaults and never executes archived binaries.
package applemanifest

import (
	"archive/zip"
	"bimeron/internal/appleversion"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/macho"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	ManifestName  = "apple-update-manifest.json"
	MaxManifest   = 65536
	SignatureSize = 89
	MaxArchive    = 268435456
	MaxBinary     = 268435456
	MaxNotice     = 4194304
	MaxEntries    = 4
)

type Compatibility struct {
	Schema              int    `json:"schema"`
	AppMin              string `json:"app_min"`
	AppMaxExclusive     string `json:"app_max_exclusive"`
	AppleReviewed       bool   `json:"apple_reviewed"`
	IPCMin              int    `json:"ipc_min"`
	IPCMax              int    `json:"ipc_max"`
	ProfileFormat       int    `json:"profile_format"`
	DaemonSessionGuards bool   `json:"daemon_session_guards"`
}
type Archive struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Schema         int           `json:"schema"`
	Product        string        `json:"product"`
	Tag            string        `json:"tag"`
	CoreVersion    string        `json:"core_version"`
	Channel        string        `json:"channel"`
	SourceRevision string        `json:"source_revision"`
	KeyID          string        `json:"key_id"`
	Compatibility  Compatibility `json:"compatibility"`
	Archives       []Archive     `json:"archives"`
}

var triplet = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var revision = regexp.MustCompile(`^[0-9a-f]{40}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var keyPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

func validVersion(v string) bool {
	return appleversion.ValidVersion(v)
}

func less(a, b string) bool {
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range aa {
		if len(aa[i]) != len(bb[i]) {
			return len(aa[i]) < len(bb[i])
		}
		if aa[i] != bb[i] {
			return aa[i] < bb[i]
		}
	}
	return false
}
func appVersion(v string) bool {
	if len(v) > 128 || !triplet.MatchString(v) {
		return false
	}
	for _, n := range strings.Split(v, ".") {
		if _, e := strconv.ParseUint(n, 10, 64); e != nil {
			return false
		}
	}
	return true
}
func (c Compatibility) validate() error {
	if c.Schema != 1 || len(c.AppMin) > 128 || len(c.AppMaxExclusive) > 128 || !appVersion(c.AppMin) || !appVersion(c.AppMaxExclusive) || !less(c.AppMin, c.AppMaxExclusive) || c.IPCMin != 1 || c.IPCMax != 1 || c.ProfileFormat != 1 || !c.DaemonSessionGuards {
		return errors.New("invalid Apple compatibility")
	}
	return nil
}
func KeyID(pub ed25519.PublicKey) string { s := sha256.Sum256(pub); return hex.EncodeToString(s[:8]) }
func (m Manifest) validate() error {
	channel := "stable"
	if strings.Contains(m.CoreVersion, "-") {
		channel = "beta"
	}
	if m.Schema != 1 || m.Product != "bimeron-apple-core" || !validVersion(m.CoreVersion) || m.Tag != "v"+m.CoreVersion || m.Channel != channel || !revision.MatchString(m.SourceRevision) || !keyPattern.MatchString(m.KeyID) {
		return errors.New("invalid Apple manifest identity")
	}
	if err := m.Compatibility.validate(); err != nil {
		return err
	}
	if len(m.Archives) != 2 {
		return errors.New("two archives required")
	}
	seen := map[string]bool{}
	for _, a := range m.Archives {
		if (a.Arch != "amd64" && a.Arch != "arm64") || seen[a.Arch] || a.OS != "macos" || a.Name != archiveName(m.Tag, a.Arch) || a.Size <= 0 || a.Size > MaxArchive || !digest.MatchString(a.SHA256) {
			return errors.New("invalid archive record")
		}
		seen[a.Arch] = true
	}
	return nil
}
func archiveName(tag, arch string) string { return "bimeron-" + tag + "-macos-" + arch + ".zip" }

// strict checks decoded key uniqueness before decoding into exact field sets.
func strict(data []byte, dst any) error {
	if len(data) == 0 || len(data) > MaxManifest || !utf8.Valid(data) || data[len(data)-1] != '\n' || len(data) < 2 || data[len(data)-2] != '}' {
		return errors.New("JSON must end with object and single LF")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		tok, e := d.Token()
		if e != nil {
			return e
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					t, e := d.Token()
					if e != nil {
						return e
					}
					k, ok := t.(string)
					if !ok || seen[strings.ToLower(k)] {
						return errors.New("duplicate JSON key")
					}
					for _, r := range k {
						if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
							return errors.New("non-ASCII or case alias key")
						}
					}
					seen[k] = true
					if e := walk(); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			case '[':
				for d.More() {
					if e := walk(); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			default:
				return errors.New("unexpected delimiter")
			}
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	// Requiring every field avoids zero-valued missing/null booleans being accepted.
	var actual map[string]json.RawMessage
	if err := json.Unmarshal(data, &actual); err != nil {
		return err
	}
	encoded, _ := json.Marshal(dst)
	var expected map[string]json.RawMessage
	json.Unmarshal(encoded, &expected)
	return fields(actual, expected)
}
func fields(actual, expected map[string]json.RawMessage) error {
	if len(actual) != len(expected) {
		return errors.New("missing fields")
	}
	for k, v := range expected {
		a, ok := actual[k]
		if !ok || bytes.Equal(bytes.TrimSpace(a), []byte("null")) {
			return errors.New("missing or null field")
		}
		if len(v) > 0 && v[0] == '{' {
			var x, y map[string]json.RawMessage
			json.Unmarshal(a, &x)
			json.Unmarshal(v, &y)
			if e := fields(x, y); e != nil {
				return e
			}
		}
		if k == "archives" {
			var x, y []map[string]json.RawMessage
			json.Unmarshal(a, &x)
			json.Unmarshal(v, &y)
			for i := range x {
				if e := fields(x[i], y[i]); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func ParseCompatibility(data []byte) (Compatibility, error) {
	var c Compatibility
	e := strict(data, &c)
	if e == nil {
		e = c.validate()
	}
	return c, e
}
func Parse(data []byte) (Manifest, error) {
	var m Manifest
	e := strict(data, &m)
	if e == nil {
		e = m.validate()
	}
	return m, e
}
func Encode(m Manifest) ([]byte, error) {
	if e := m.validate(); e != nil {
		return nil, e
	}
	b, e := json.MarshalIndent(m, "", "  ")
	b = append(b, '\n')
	if len(b) > MaxManifest {
		return nil, errors.New("manifest too large")
	}
	return b, e
}

// Prepare validates final archive bytes; pub is an explicit identifier, not a trust pin.
func Prepare(tag, rev string, c Compatibility, pub ed25519.PublicKey, archives map[string][]byte) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("public key required")
	}
	m := Manifest{Schema: 1, Product: "bimeron-apple-core", Tag: tag, CoreVersion: strings.TrimPrefix(tag, "v"), SourceRevision: rev, Channel: "stable", KeyID: KeyID(pub), Compatibility: c}
	if strings.Contains(m.CoreVersion, "-") {
		m.Channel = "beta"
	}
	for _, arch := range []string{"amd64", "arm64"} {
		b := archives[arch]
		if len(b) == 0 || len(b) > MaxArchive {
			return nil, errors.New("archive size")
		}
		s := sha256.Sum256(b)
		m.Archives = append(m.Archives, Archive{"macos", arch, archiveName(tag, arch), int64(len(b)), hex.EncodeToString(s[:])})
	}
	if e := m.validate(); e != nil {
		return nil, e
	}
	if len(archives) != 2 {
		return nil, errors.New("unexpected archives")
	}
	for _, a := range m.Archives {
		if e := CheckArchive(archives[a.Arch], a.Arch, rev, m.CoreVersion); e != nil {
			return nil, e
		}
	}
	return Encode(m)
}

// Sign has no environment or file key loading. Callers own authorization.
func Sign(data []byte, key ed25519.PrivateKey) ([]byte, error) {
	if _, e := Parse(data); e != nil {
		return nil, e
	}
	if len(key) != 64 || !bytes.Equal(ed25519.NewKeyFromSeed(key[:32]), key) {
		return nil, errors.New("invalid key")
	}
	m, _ := Parse(data)
	if m.KeyID != KeyID(key.Public().(ed25519.PublicKey)) {
		return nil, errors.New("signing key identifier mismatch")
	}
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, data)) + "\n"), nil
}

// VerifiedManifest is an authenticated, locally approved descriptor, not verified ZIP bytes.
type VerifiedManifest struct{ manifest Manifest }

// Manifest returns a copy of the authenticated descriptor.
func (v VerifiedManifest) Manifest() Manifest {
	m := v.manifest
	m.Archives = append([]Archive(nil), m.Archives...)
	return m
}

// VerifyManifest authenticates exact received bytes using independent explicit trust.
func VerifyManifest(data, sig []byte, pub ed25519.PublicKey, tag, rev string) (VerifiedManifest, error) {
	fail := func(e error) (VerifiedManifest, error) { return VerifiedManifest{}, e }
	if len(pub) != 32 || len(data) > MaxManifest || len(sig) != SignatureSize {
		return fail(errors.New("missing trust or invalid envelope"))
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(string(sig[:88]))
	if e != nil || len(raw) != 64 || string(sig) != base64.StdEncoding.EncodeToString(raw)+"\n" || !ed25519.Verify(pub, data, raw) {
		return fail(errors.New("invalid signature"))
	}
	m, e := Parse(data)
	if e != nil {
		return fail(e)
	}
	if m.Tag != tag || m.SourceRevision != rev || !revision.MatchString(rev) || m.KeyID != KeyID(pub) || !m.Compatibility.AppleReviewed {
		return fail(errors.New("release not locally approved and reviewed"))
	}
	return VerifiedManifest{m}, nil
}

// VerifyArchives checks all final byte hashes before parsing any archive. It neither
// extracts files nor proves runtime readiness. A zero descriptor fails closed.
func (v VerifiedManifest) VerifyArchives(archives map[string][]byte) error {
	m := v.manifest
	if e := m.validate(); e != nil {
		return e
	}
	if len(archives) != 2 {
		return errors.New("two archives required")
	}
	for _, a := range m.Archives {
		b := archives[a.Arch]
		s := sha256.Sum256(b)
		if int64(len(b)) != a.Size || hex.EncodeToString(s[:]) != a.SHA256 {
			return errors.New("archive bytes mismatch")
		}
	}
	for _, a := range m.Archives {
		if e := CheckArchive(archives[a.Arch], a.Arch, m.SourceRevision, m.CoreVersion); e != nil {
			return e
		}
	}
	return nil
}

func CheckArchive(data []byte, arch, rev, version string) error {
	if (arch != "amd64" && arch != "arm64") || !revision.MatchString(rev) || !validVersion(version) {
		return errors.New("invalid archive identity")
	}
	if len(data) == 0 || len(data) > MaxArchive {
		return errors.New("archive size")
	}
	z, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil {
		return e
	}
	if len(z.File) < 3 || len(z.File) > MaxEntries {
		return errors.New("archive entry count")
	}
	parent := "macos-" + arch + "/"
	seen := map[string]bool{}
	for _, f := range z.File {
		name := f.Name
		if seen[name] || f.Flags&1 != 0 || (f.Method != zip.Store && f.Method != zip.Deflate) {
			return errors.New("duplicate/encrypted/unsupported ZIP entry")
		}
		seen[name] = true
		if name == parent {
			if f.Mode().Type() != os.ModeDir || f.UncompressedSize64 != 0 {
				return errors.New("invalid parent directory")
			}
			continue
		}
		limit := uint64(MaxNotice)
		switch name {
		case parent + "bimeron":
			limit = MaxBinary
		case parent + "LICENSE", parent + "THIRD_PARTY_NOTICES.txt":
		default:
			return errors.New("unexpected ZIP path")
		}
		if !f.Mode().IsRegular() || f.UncompressedSize64 == 0 || f.UncompressedSize64 > limit {
			return errors.New("invalid regular ZIP file")
		}
		if name == parent+"bimeron" && f.Mode().Perm()&0111 == 0 {
			return errors.New("binary not executable")
		}
		r, e := f.Open()
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(r, int64(limit)+1))
		ce := r.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		if uint64(len(b)) != f.UncompressedSize64 {
			return errors.New("uncompressed size mismatch")
		}
		if name == parent+"bimeron" {
			if e := checkBinary(b, arch, rev, version); e != nil {
				return e
			}
		}
	}
	for _, n := range []string{"bimeron", "LICENSE", "THIRD_PARTY_NOTICES.txt"} {
		if !seen[parent+n] {
			return errors.New("missing archive file")
		}
	}
	return nil
}
func checkBinary(b []byte, arch, rev, version string) error {
	f, e := macho.NewFile(bytes.NewReader(b))
	if e != nil {
		return e
	}
	defer f.Close()
	cpu := macho.CpuAmd64
	if arch == "arm64" {
		cpu = macho.CpuArm64
	} else if arch != "amd64" {
		return errors.New("unsupported architecture")
	}
	if f.Cpu != cpu || f.Type != macho.TypeExec {
		return errors.New("wrong Mach-O architecture/type")
	}
	info, e := buildinfo.Read(bytes.NewReader(b))
	if e != nil {
		return e
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		if _, ok := settings[s.Key]; ok {
			return errors.New("duplicate build setting")
		}
		settings[s.Key] = s.Value
	}
	if settings["GOOS"] != "darwin" || settings["GOARCH"] != arch || settings["vcs.revision"] != rev || settings["vcs.modified"] != "false" {
		return errors.New("missing or mismatched build provenance")
	}
	if settings["vcs"] != "git" || settings["-trimpath"] != "true" {
		return errors.New("missing Apple build recipe evidence")
	}
	recovered, err := appleversion.SectionVersion(f, uint64(len(b)))
	if err != nil {
		return err
	}
	if recovered != version {
		return errors.New("Core version record mismatch")
	}
	return nil
}
