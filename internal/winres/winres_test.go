package winres

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func sourceIcon(t testing.TB) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "assets", "brand", "bimeron.ico"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSourceIcon(t *testing.T) {
	images, err := ParseICO(sourceIcon(t))
	if err != nil {
		t.Fatal(err)
	}
	var sizes []int
	for _, image := range images {
		if image.Width != image.Height || !image.PNG() || image.BitCount != 32 {
			t.Errorf("image %dx%d: want square 32-bit PNG", image.Width, image.Height)
		}
		sizes = append(sizes, image.Width)
	}
	// build-apple.sh derives the macOS iconset from these sizes.
	for _, size := range []int{16, 32, 64, 128, 256} {
		if !slices.Contains(sizes, size) {
			t.Errorf("sizes %v lack %d px", sizes, size)
		}
	}
}

func TestSourceIconProvenance(t *testing.T) {
	sum := sha256.Sum256(sourceIcon(t))
	readme, err := os.ReadFile(filepath.Join("..", "..", "assets", "brand", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), hex.EncodeToString(sum[:])) {
		t.Fatal("assets/brand/README.md does not record the SHA-256 of bimeron.ico; update its provenance")
	}
}

func TestLegalCopyrightMatchesLicense(t *testing.T) {
	license, err := os.ReadFile(filepath.Join("..", "..", "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(license), LegalCopyright+"\n") && !strings.Contains(string(license), LegalCopyright+"\r\n") {
		t.Fatalf("LICENSE does not contain %q", LegalCopyright)
	}
}

func icoFile(entries ...[]byte) []byte {
	b := []byte{0, 0, 1, 0}
	b = binary.LittleEndian.AppendUint16(b, uint16(len(entries)))
	offset := 6 + 16*len(entries)
	for _, data := range entries {
		b = append(b, 16, 16, 0, 0, 1, 0, 32, 0)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
		b = binary.LittleEndian.AppendUint32(b, uint32(offset))
		offset += len(data)
	}
	for _, data := range entries {
		b = append(b, data...)
	}
	return b
}

func TestParseICORejectsMalformed(t *testing.T) {
	valid := icoFile([]byte("image"))
	if _, err := ParseICO(valid); err != nil {
		t.Fatal(err)
	}
	cursor := slices.Clone(valid)
	cursor[2] = 2
	outside := slices.Clone(valid)
	binary.LittleEndian.PutUint32(outside[6+8:], 1000)
	overlapping := slices.Clone(valid)
	binary.LittleEndian.PutUint32(overlapping[6+12:], 0)
	for name, data := range map[string][]byte{
		"empty":       nil,
		"cursor":      cursor,
		"no images":   {0, 0, 1, 0, 0, 0},
		"truncated":   valid[:10],
		"outside":     outside,
		"overlapping": overlapping,
	} {
		if _, err := ParseICO(data); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for _, tc := range []struct {
		in         string
		fixed      [4]uint16
		text       string
		prerelease bool
	}{
		{"", [4]uint16{}, DevVersion, true},
		{"0.4.0-beta.1", [4]uint16{0, 4, 0, 0}, "0.4.0-beta.1", true},
		{"0.3.2-dev", [4]uint16{0, 3, 2, 0}, "0.3.2-dev", true},
		{"1.2.3", [4]uint16{1, 2, 3, 0}, "1.2.3", false},
		{"1.2.3+abc", [4]uint16{1, 2, 3, 0}, "1.2.3+abc", false},
		{"65535.0.1", [4]uint16{65535, 0, 1, 0}, "65535.0.1", false},
	} {
		v, err := ParseVersion(tc.in)
		if err != nil || v.Fixed != tc.fixed || v.Text != tc.text || v.Prerelease != tc.prerelease {
			t.Errorf("ParseVersion(%q) = %+v, %v", tc.in, v, err)
		}
	}
	for _, in := range []string{"v1.2.3", "1.2", "1.2.3.4", "01.2.3", "65536.0.0", "1.2.3-", "dev", "1.2.3 "} {
		if _, err := ParseVersion(in); err == nil {
			t.Errorf("ParseVersion(%q) succeeded", in)
		}
	}
}

func TestVersionInfoRoundTrip(t *testing.T) {
	for _, text := range []string{"", "0.4.0-beta.1", "1.0.0"} {
		v, err := ParseVersion(text)
		if err != nil {
			t.Fatal(err)
		}
		data := versionInfo(v)
		if int(binary.LittleEndian.Uint16(data)) != len(data) {
			t.Fatalf("%q: wLength %d, encoded %d bytes", text, binary.LittleEndian.Uint16(data), len(data))
		}
		info, err := ParseVersionInfo(data)
		if err != nil {
			t.Fatal(err)
		}
		if info.FileVersion != v.Fixed || info.ProductVersion != v.Fixed || info.FileType != fixedTypeApp {
			t.Errorf("%q: fixed info %+v", text, info)
		}
		if (info.FileFlags == fixedPrerelease) != v.Prerelease {
			t.Errorf("%q: flags %#x", text, info.FileFlags)
		}
		for _, kv := range versionStrings(v) {
			if info.Strings[kv[0]] != kv[1] {
				t.Errorf("%q: %s = %q, want %q", text, kv[0], info.Strings[kv[0]], kv[1])
			}
		}
		if len(info.Strings) != len(versionStrings(v)) {
			t.Errorf("%q: strings %v", text, info.Strings)
		}
	}
	if _, err := ParseVersionInfo([]byte{4, 0, 0, 0}); err == nil {
		t.Error("parsed a truncated block")
	}
}

func TestObjectCOFF(t *testing.T) {
	ico := sourceIcon(t)
	for arch, want := range map[string]struct {
		machine uint16
		reloc   uint16
	}{
		"amd64": {pe.IMAGE_FILE_MACHINE_AMD64, 3},
		"arm64": {pe.IMAGE_FILE_MACHINE_ARM64, 2},
	} {
		obj, err := Object(arch, ico, "0.4.0-beta.1")
		if err != nil {
			t.Fatal(err)
		}
		again, err := Object(arch, ico, "0.4.0-beta.1")
		if err != nil || !bytes.Equal(obj, again) {
			t.Fatalf("%s: output is not deterministic", arch)
		}
		f, err := pe.NewFile(bytes.NewReader(obj))
		if err != nil {
			t.Fatal(err)
		}
		if f.Machine != want.machine || len(f.Sections) != 1 || f.Sections[0].Name != ".rsrc" {
			t.Fatalf("%s: machine %#x sections %d", arch, f.Machine, len(f.Sections))
		}
		s := f.Sections[0]
		if s.Characteristics != pe.IMAGE_SCN_CNT_INITIALIZED_DATA|pe.IMAGE_SCN_MEM_READ {
			t.Errorf("%s: characteristics %#x", arch, s.Characteristics)
		}
		// Seven icon images, the icon group and VERSIONINFO.
		if len(s.Relocs) != 9 {
			t.Fatalf("%s: %d relocations", arch, len(s.Relocs))
		}
		for _, r := range s.Relocs {
			if r.Type != want.reloc || r.SymbolTableIndex != 0 {
				t.Errorf("%s: relocation %+v", arch, r)
			}
		}
		if len(f.COFFSymbols) != 1 || f.COFFSymbols[0].SectionNumber != 1 || f.COFFSymbols[0].StorageClass != 3 {
			t.Errorf("%s: symbols %+v", arch, f.COFFSymbols)
		}
	}
	if _, err := Object("386", ico, ""); err == nil {
		t.Error("accepted an unsupported architecture")
	}
	if _, err := Object("amd64", ico, "v1.0.0"); err == nil {
		t.Error("accepted an invalid version")
	}
	if _, err := Object("amd64", []byte("not an icon"), ""); err == nil {
		t.Error("accepted an invalid icon")
	}
}

func TestResourceSectionRejectsDuplicates(t *testing.T) {
	r := Resource{Type: TypeIcon, ID: 1, Language: Language, Data: []byte{1}}
	if _, _, err := resourceSection([]Resource{r, r}); err == nil {
		t.Fatal("accepted duplicate resources")
	}
}

func BenchmarkObject(b *testing.B) {
	ico := sourceIcon(b)
	for b.Loop() {
		if _, err := Object("amd64", ico, "0.4.0-beta.1"); err != nil {
			b.Fatal(err)
		}
	}
}
