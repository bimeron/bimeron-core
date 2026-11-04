package prototype

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/macho"
	"fmt"
	"io"
	"os"
	"regexp"
)

const Prefix = "BIMERON.APPLE.CORE.VERSION/v1\x00"
const suffix = "\x00END.APPLE.CORE.RECORD/v1\x00"
const MaxVersion = 128
const MaxSection = 64 << 20
const MaxFile = 256 << 20

var semver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$`)

func validVersion(v string) bool {
	if len(v) == 0 || len(v) > MaxVersion || !semver.MatchString(v) {
		return false
	}
	pre := []byte(v)
	if i := bytes.IndexByte(pre, '-'); i >= 0 {
		for _, id := range bytes.Split(pre[i+1:], []byte(".")) {
			numeric := true
			for _, c := range id {
				if c < '0' || c > '9' {
					numeric = false
				}
			}
			if numeric && len(id) > 1 && id[0] == '0' {
				return false
			}
		}
	}
	return true
}

func Frame(v string) ([]byte, error) {
	if !validVersion(v) {
		return nil, fmt.Errorf("invalid SemVer")
	}
	return []byte(fmt.Sprintf("%s%03d:%s%s", Prefix, len(v), v, suffix)), nil
}

// Parse permits surrounding section bytes, but exactly one full domain prefix.
func Parse(data []byte) (string, error) {
	if len(data) > MaxSection || bytes.Count(data, []byte(Prefix)) != 1 {
		return "", fmt.Errorf("record missing, duplicated, or section oversized")
	}
	p := bytes.Index(data, []byte(Prefix)) + len(Prefix)
	if len(data)-p < 4 {
		return "", fmt.Errorf("truncated length")
	}
	n := 0
	for _, c := range data[p : p+3] {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("invalid length")
		}
		n = n*10 + int(c-'0')
	}
	if data[p+3] != ':' || n < 1 || n > MaxVersion || len(data)-(p+4) < n+len(suffix) {
		return "", fmt.Errorf("invalid record bounds")
	}
	v := string(data[p+4 : p+4+n])
	canonical, err := Frame(v)
	if err != nil {
		return "", err
	}
	start := p - len(Prefix)
	if !bytes.Equal(data[start:start+len(canonical)], canonical) {
		return "", fmt.Errorf("noncanonical framing")
	}
	return v, nil
}

type Expected struct {
	Version, Revision, Arch string
	SHA256                  [32]byte
}

// Verify first binds bytes to a caller-authenticated digest. This prototype does
// not authenticate a sidecar or use keys; callers must establish that trust.
func Verify(path string, want Expected) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxFile {
		return fmt.Errorf("invalid file size or type")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxFile+1))
	if err != nil {
		return err
	}
	if len(data) > MaxFile {
		return fmt.Errorf("file oversized")
	}
	if sha256.Sum256(data) != want.SHA256 {
		return fmt.Errorf("hash mismatch")
	}
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer f.Close()
	cpu := macho.CpuArm64
	if want.Arch == "amd64" {
		cpu = macho.CpuAmd64
	} else if want.Arch != "arm64" {
		return fmt.Errorf("unsupported arch")
	}
	if f.Type != macho.TypeExec || f.Cpu != cpu {
		return fmt.Errorf("thin executable CPU mismatch")
	}
	var record []byte
	for _, s := range f.Sections {
		if s.Seg == "__TEXT" && s.Name == "__rodata" {
			if record != nil || s.Size > MaxSection {
				return fmt.Errorf("invalid record section")
			}
			// Require a read-only segment, not merely a section with a familiar name.
			seg := f.Segment(s.Seg)
			if seg == nil || seg.Prot&2 != 0 {
				return fmt.Errorf("writable record segment")
			}
			record, err = s.Data()
			if err != nil {
				return err
			}
		}
	}
	v, err := Parse(record)
	if err != nil {
		return err
	}
	if v != want.Version {
		return fmt.Errorf("version mismatch")
	}
	bi, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return err
	}
	settings := map[string]string{}
	for _, s := range bi.Settings {
		if _, ok := settings[s.Key]; ok {
			return fmt.Errorf("duplicate build setting")
		}
		settings[s.Key] = s.Value
	}
	for k, v := range map[string]string{"GOOS": "darwin", "GOARCH": want.Arch, "vcs": "git", "vcs.revision": want.Revision, "vcs.modified": "false", "-trimpath": "true"} {
		if settings[k] != v {
			return fmt.Errorf("build setting %s mismatch: %q", k, settings[k])
		}
	}
	return nil
}
