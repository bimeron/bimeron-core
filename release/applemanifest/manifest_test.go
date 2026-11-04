package applemanifest

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/apple-update-manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// Exercise Git's checkout conversion, including an unprotected CRLF control.
func TestWindowsCheckoutFixtureBytes(t *testing.T) {
	git := "<LOCAL_HOME>/.local/bin/git"
	if _, e := os.Stat(git); e != nil {
		var err error
		git, err = exec.LookPath("git")
		if err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	command(t, dir, git, "init", "-q")
	paths := []string{
		".gitattributes",
		"release/apple-compatibility.json",
		"release/applemanifest/testdata/apple-update-manifest.json",
		"release/applemanifest/testdata/synthetic-vector.json",
		"release/applemanifest/testdata/synthetic-reviewed-manifest.json",
		"release/applemanifest/testdata/synthetic-reviewed-manifest.json.sig",
	}
	original := map[string][]byte{"control.txt": []byte("checkout control\n")}
	for _, path := range paths {
		b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		original[path] = b
	}
	for path, b := range original {
		dest := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	command(t, dir, git, "-c", "core.autocrlf=false", "add", ".")
	for path := range original {
		if err := os.Remove(filepath.Join(dir, filepath.FromSlash(path))); err != nil {
			t.Fatal(err)
		}
	}
	command(t, dir, git, "-c", "core.autocrlf=true", "checkout-index", "--all", "--force")
	for path, want := range original {
		if path == ".gitattributes" {
			continue
		}
		if path == "control.txt" {
			want = []byte("checkout control\r\n")
		}
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Windows checkout changed %s bytes", path)
		}
	}
}

func syntheticKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(make([]byte, 32)) }
func TestSyntheticInterop(t *testing.T) {
	b, e := os.ReadFile("testdata/synthetic-reviewed-manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	s, e := os.ReadFile("testdata/synthetic-reviewed-manifest.json.sig")
	if e != nil {
		t.Fatal(e)
	}
	key := syntheticKey()
	pub := key.Public().(ed25519.PublicKey)
	if KeyID(pub) != "139e3940e64b5491" || base64.StdEncoding.EncodeToString(pub) != "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=" {
		t.Fatal("key vector changed")
	}
	if string(s) != "uTMOopFrg18RlQMJnkSDR9sMDiM6MvdFGefnFA1VCe/0l/eXDE7bxZK6SwXHz179Zx2O08CJw/9T+jYG/INXBw==\n" {
		t.Fatal("fixed signature changed")
	}
	signed, e := Sign(b, key)
	if e != nil || !bytes.Equal(s, signed) {
		t.Fatal("signature vector changed", e)
	}
	m, e := Parse(b)
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := Encode(m)
	if e != nil || !bytes.Equal(b, encoded) {
		t.Fatal("nondeterministic encoding", e)
	}
	v, e := VerifyManifest(b, s, pub, m.Tag, m.SourceRevision)
	if e != nil {
		t.Fatal(e)
	}
	copy := v.Manifest()
	copy.Archives[0].Name = "mutated"
	if v.Manifest().Archives[0].Name == "mutated" {
		t.Fatal("descriptor mutable")
	}
	if e := v.VerifyArchives(map[string][]byte{"amd64": {0}, "arm64": {0}}); e == nil {
		t.Fatal("placeholder archives accepted")
	}
	cases := []struct {
		name      string
		data, sig []byte
		pub       ed25519.PublicKey
		tag, rev  string
	}{
		{"tamper", bytes.Replace(b, []byte("beta.1"), []byte("beta.2"), 1), s, pub, m.Tag, m.SourceRevision},
		{"whitespace", append(append([]byte(nil), b...), ' '), s, pub, m.Tag, m.SourceRevision},
		{"signature LF", b, s[:88], pub, m.Tag, m.SourceRevision},
		{"signature CRLF", b, append(append([]byte(nil), s[:88]...), '\r', '\n'), pub, m.Tag, m.SourceRevision},
		{"wrong pin", b, s, make([]byte, 32), m.Tag, m.SourceRevision},
		{"absent pin", b, s, nil, m.Tag, m.SourceRevision},
		{"unapproved tag", b, s, pub, "", m.SourceRevision},
		{"unapproved revision", b, s, pub, m.Tag, strings.Repeat("1", 40)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, e := VerifyManifest(c.data, c.sig, c.pub, c.tag, c.rev); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	m.Compatibility.AppleReviewed = false
	unsigned, _ := Encode(m)
	unreviewed, _ := Sign(unsigned, key)
	if _, e := VerifyManifest(unsigned, unreviewed, pub, m.Tag, m.SourceRevision); e == nil {
		t.Fatal("unreviewed accepted")
	}
	if _, e := Sign(b, make([]byte, 64)); e == nil {
		t.Fatal("invalid key accepted")
	}
	if e := (VerifiedManifest{}).VerifyArchives(nil); e == nil {
		t.Fatal("zero descriptor accepted")
	}
	// Signing different interior whitespace verifies exact bytes without canonicalization.
	alternate := bytes.ReplaceAll(b, []byte("  "), []byte("\t"))
	sig, e := Sign(alternate, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := VerifyManifest(alternate, sig, pub, m.Tag, m.SourceRevision); e != nil {
		t.Fatal(e)
	}
}
func TestStrictContract(t *testing.T) {
	b := fixture(t)
	if _, e := Parse(b); e != nil {
		t.Fatal(e)
	}
	cases := map[string][]byte{
		"nested duplicate":          bytes.Replace(b, []byte(`"ipc_min": 1`), []byte(`"ipc_min": 1, "ipc_min": 1`), 1),
		"archive escaped duplicate": bytes.Replace(b, []byte(`"size": 1`), []byte(`"size": 1, "\u0073ize": 1`), 1),
		"nested missing":            bytes.Replace(b, []byte(`    "apple_reviewed": false,`), nil, 1),
		"archive null":              bytes.Replace(b, []byte(`"arch": "amd64"`), []byte(`"arch": null`), 1),
		"archive fraction":          bytes.Replace(b, []byte(`"size": 1`), []byte(`"size": 1.00000000000000001`), 1),
		"IPC exponent":              bytes.Replace(b, []byte(`"ipc_min": 1`), []byte(`"ipc_min": 1e0`), 1),

		"duplicate":          bytes.Replace(b, []byte(`"schema": 1`), []byte(`"schema": 1, "schema": 1`), 1),
		"escaped duplicate":  bytes.Replace(b, []byte(`"schema": 1`), []byte(`"schema": 1, "\u0073chema": 1`), 1),
		"case alias":         bytes.Replace(b, []byte(`"schema": 1`), []byte(`"schema": 1, "Schema": 1`), 1),
		"unknown":            bytes.Replace(b, []byte(`"schema": 1`), []byte(`"unknown": 1, "schema": 1`), 1),
		"nested unknown":     bytes.Replace(b, []byte(`"ipc_min": 1`), []byte(`"extra": 1, "ipc_min": 1`), 1),
		"archive unknown":    bytes.Replace(b, []byte(`"size": 1`), []byte(`"extra": 1, "size": 1`), 1),
		"unsupported schema": bytes.Replace(b, []byte(`"schema": 1`), []byte(`"schema": 2`), 1),
		"nested schema":      bytes.ReplaceAll(b, []byte(`"schema": 1`), []byte(`"schema": 2`)),
		"fraction":           bytes.Replace(b, []byte(`"schema": 1`), []byte(`"schema": 1.00000000000000001`), 1),
		"exponent":           bytes.Replace(b, []byte(`"schema": 1`), []byte(`"schema": 1e0`), 1),
		"negative zero":      bytes.Replace(b, []byte(`"size": 1`), []byte(`"size": -0`), 1),
		"leading zero":       bytes.Replace(b, []byte(`"size": 1`), []byte(`"size": 01`), 1),
		"missing":            bytes.Replace(b, []byte(`  "schema": 1,`), nil, 1),
		"null":               bytes.Replace(b, []byte(`"apple_reviewed": false`), []byte(`"apple_reviewed": null`), 1),
		"no LF":              b[:len(b)-1], "two LF": append(append([]byte(nil), b...), '\n'),
		"space after object": append(append([]byte(nil), b[:len(b)-1]...), ' ', '\n'),
		"trailing object":    append(append([]byte(nil), b...), '{', '}', '\n'),
		"invalid UTF8":       append([]byte{255}, b...), "oversize": bytes.Repeat([]byte(" "), MaxManifest+1),
	}
	for n, b := range cases {
		t.Run(n, func(t *testing.T) {
			if _, e := Parse(b); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	m, _ := Parse(b)
	mutations := map[string]func(*Manifest){
		"product": func(m *Manifest) { m.Product = "bimeron" }, "revision": func(m *Manifest) { m.SourceRevision = strings.Repeat("A", 40) }, "key ID": func(m *Manifest) { m.KeyID = "139e3940" },
		"channel": func(m *Manifest) { m.Channel = "stable" }, "tag": func(m *Manifest) { m.Tag = "v0.2.0" }, "semver leading zero": func(m *Manifest) { m.CoreVersion = "01.0.0" }, "prerelease zero": func(m *Manifest) { m.CoreVersion = "0.1.0-beta.01" },
		"app overflow": func(m *Manifest) { m.Compatibility.AppMaxExclusive = "18446744073709551616.0.0" }, "empty interval": func(m *Manifest) { m.Compatibility.AppMaxExclusive = "0.1.0" }, "reverse interval": func(m *Manifest) { m.Compatibility.AppMin = "0.2.0" },
		"guards": func(m *Manifest) { m.Compatibility.DaemonSessionGuards = false }, "IPC": func(m *Manifest) { m.Compatibility.IPCMax = 2 }, "profile": func(m *Manifest) { m.Compatibility.ProfileFormat = 2 },
		"archive count": func(m *Manifest) { m.Archives = m.Archives[:1] }, "duplicate arch": func(m *Manifest) { m.Archives[1] = m.Archives[0] }, "OS": func(m *Manifest) { m.Archives[0].OS = "darwin" }, "name": func(m *Manifest) { m.Archives[0].Name = "../x" }, "hash": func(m *Manifest) { m.Archives[0].SHA256 = strings.Repeat("A", 64) }, "size": func(m *Manifest) { m.Archives[0].Size = MaxArchive + 1 },
	}
	for n, mutate := range mutations {
		t.Run(n, func(t *testing.T) {
			copy := m
			copy.Archives = append([]Archive(nil), m.Archives...)
			mutate(&copy)
			raw, _ := json.Marshal(copy)
			if _, e := Parse(append(raw, '\n')); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	if !appVersion("18446744073709551615.0.0") {
		t.Fatal("UInt64 maximum rejected")
	}
	cdata, e := os.ReadFile("../apple-compatibility.json")
	if e != nil {
		t.Fatal(e)
	}
	c, e := ParseCompatibility(cdata)
	if e != nil || c.AppleReviewed {
		t.Fatal("shipping review must remain false", e)
	}
	// The four-target legacy manifest remains a separate incompatible product.
	legacy := bytes.Replace(b, []byte(`"product": "bimeron-apple-core",`), nil, 1)
	if _, e := Parse(legacy); e == nil {
		t.Fatal("legacy-shaped manifest accepted")
	}
}

type entry struct {
	name   string
	mode   os.FileMode
	data   []byte
	method uint16
	flags  uint16
}

func zipBytes(t *testing.T, entries []entry) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: e.method, Flags: e.flags}
		h.SetMode(e.mode)
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func entries(arch string, bin []byte) []entry {
	p := "macos-" + arch + "/"
	return []entry{{p + "bimeron", 0755, bin, zip.Deflate, 0}, {p + "LICENSE", 0644, []byte("synthetic license"), zip.Store, 0}, {p + "THIRD_PARTY_NOTICES.txt", 0644, []byte("synthetic notices"), zip.Deflate, 0}}
}
func command(t *testing.T, dir, exe string, args ...string) string {
	t.Helper()
	c := exec.Command(exe, args...)
	c.Dir = dir
	c.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off")
	b, e := c.CombinedOutput()
	if e != nil {
		t.Fatalf("%s: %v: %s", exe, e, b)
	}
	return strings.TrimSpace(string(b))
}
func buildFixtures(t *testing.T) (map[string][]byte, map[string][]byte, string) {
	t.Helper()
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "core"), 0755)
	for name, body := range map[string]string{"go.mod": "module bimeron\n\ngo 1.26.9\n", "core/version.go": "package core\nvar Version=\"dev\"\n", "main.go": "package main\nimport (\"fmt\";\"bimeron/core\")\nfunc main(){fmt.Println(core.Version)}\n"} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); e != nil {
			t.Fatal(e)
		}
	}
	git := "<LOCAL_HOME>/.local/bin/git"
	if _, e := os.Stat(git); e != nil { // CI uses its own scoped executable.
		git, e = exec.LookPath("git")
		if e != nil {
			t.Fatal(e)
		}
	}
	command(t, dir, git, "init", "-q")
	command(t, dir, git, "add", "go.mod", "core/version.go", "main.go")
	command(t, dir, git, "-c", "user.name=Synthetic Test", "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "test: synthetic build fixture")
	rev := command(t, dir, git, "rev-parse", "HEAD")
	goexe := filepath.Join(runtime.GOROOT(), "bin", "go")
	plain, trim := map[string][]byte{}, map[string][]byte{}
	for _, arch := range []string{"amd64", "arm64"} {
		for _, trimpath := range []bool{false, true} {
			out := filepath.Join(t.TempDir(), "fixture")
			args := []string{"build", "-buildvcs=true", "-ldflags", "-s -w -X bimeron/core.Version=0.1.0-beta.1", "-o", out}
			if trimpath {
				args = append(args, "-trimpath")
			}
			args = append(args, ".")
			c := exec.Command(goexe, args...)
			c.Dir = dir
			c.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOOS=darwin", "GOARCH="+arch, "CGO_ENABLED=0")
			if b, e := c.CombinedOutput(); e != nil {
				t.Fatalf("cross-build: %v %s", e, b)
			}
			b, e := os.ReadFile(out)
			if e != nil {
				t.Fatal(e)
			}
			if trimpath {
				trim[arch] = b
			} else {
				plain[arch] = b
			}
		}
	}
	return plain, trim, rev
}
func TestBuildProvenanceAndArchives(t *testing.T) {
	plain, trim, rev := buildFixtures(t)
	key := syntheticKey()
	pub := key.Public().(ed25519.PublicKey)
	m, err := Parse(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	c := m.Compatibility
	c.AppleReviewed = true
	archives := map[string][]byte{}
	for _, arch := range []string{"amd64", "arm64"} {
		if e := checkBinary(plain[arch], arch, rev, m.CoreVersion); e != nil {
			t.Fatal(e)
		}
		if e := checkBinary(trim[arch], arch, rev, m.CoreVersion); e == nil || !strings.Contains(e.Error(), "Core version") {
			t.Fatalf("actual build-dist flags must fail missing ldflags evidence: %v", e)
		}
		archives[arch] = zipBytes(t, entries(arch, plain[arch]))
		if e := CheckArchive(archives[arch], arch, rev, m.CoreVersion); e != nil {
			t.Fatal(e)
		}
		withParent := append(entries(arch, plain[arch]), entry{"macos-" + arch + "/", os.ModeDir | 0755, nil, zip.Store, 0})
		if e := CheckArchive(zipBytes(t, withParent), arch, rev, m.CoreVersion); e != nil {
			t.Fatal(e)
		}
	}
	b, e := Prepare(m.Tag, rev, c, pub, archives)
	if e != nil {
		t.Fatal(e)
	}
	again, e := Prepare(m.Tag, rev, c, pub, archives)
	if e != nil || !bytes.Equal(b, again) {
		t.Fatal("preparation nondeterministic", e)
	}
	sig, _ := Sign(b, key)
	v, e := VerifyManifest(b, sig, pub, m.Tag, rev)
	if e != nil {
		t.Fatal(e)
	}
	if e := v.VerifyArchives(archives); e != nil {
		t.Fatal(e)
	}
	tampered := map[string][]byte{"amd64": archives["amd64"], "arm64": []byte("not ZIP")}
	if e := v.VerifyArchives(tampered); e == nil || e.Error() != "archive bytes mismatch" {
		t.Fatal("must hash before parsing", e)
	}
	// Both record orders are accepted.
	parsed, _ := Parse(b)
	parsed.Archives[0], parsed.Archives[1] = parsed.Archives[1], parsed.Archives[0]
	reversed, _ := Encode(parsed)
	rs, _ := Sign(reversed, key)
	if _, e := VerifyManifest(reversed, rs, pub, m.Tag, rev); e != nil {
		t.Fatal(e)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		other := "arm64"
		if arch == "arm64" {
			other = "amd64"
		}
		for name, args := range map[string][]string{"wrong arch": {other, rev, m.CoreVersion}, "wrong revision": {arch, strings.Repeat("0", 40), m.CoreVersion}, "wrong version": {arch, rev, "0.1.1"}} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				if e := checkBinary(plain[arch], args[0], args[1], args[2]); e == nil {
					t.Fatal("accepted")
				}
			})
		}
		// Patch only synthetic build-info strings to cover explicit missing/dirty settings.
		for _, pair := range [][2]string{{"vcs.modified=false", "vcs.modified=true "}, {"vcs.modified=false", "xxx.modified=false"}, {"vcs.revision=", "xxx.revision="}, {"bimeron/core.Version=", "bimeron/core.VersioX="}, {"GOOS=darwin", "GOOS=linuxx"}, {"GOARCH=" + arch, "GOARCX=" + arch}} {
			bad := bytes.ReplaceAll(plain[arch], []byte(pair[0]), []byte(pair[1]))
			if bytes.Equal(bad, plain[arch]) {
				t.Fatalf("missing fixture setting %s", pair[0])
			}
			if e := checkBinary(bad, arch, rev, m.CoreVersion); e == nil {
				t.Fatalf("accepted %s", pair[1])
			}
		}
	}
	badEntries := map[string]func([]entry) []entry{
		"extra": func(e []entry) []entry { return append(e, entry{"extra", 0644, []byte("x"), 0, 0}) }, "missing": func(e []entry) []entry { return e[:2] }, "duplicate": func(e []entry) []entry { return append(e, e[0]) },
		"absolute": func(e []entry) []entry { e[1].name = "/macos-amd64/LICENSE"; return e }, "backslash": func(e []entry) []entry { e[1].name = `macos-amd64\LICENSE`; return e }, "dot": func(e []entry) []entry { e[1].name = "macos-amd64/./LICENSE"; return e }, "dotdot": func(e []entry) []entry { e[1].name = "macos-amd64/../macos-amd64/LICENSE"; return e }, "alias": func(e []entry) []entry { e[1].name = "macos-amd64//LICENSE"; return e },
		"symlink": func(e []entry) []entry { e[1].mode = os.ModeSymlink | 0777; return e }, "special": func(e []entry) []entry { e[1].mode = os.ModeNamedPipe | 0644; return e }, "not executable": func(e []entry) []entry { e[0].mode = 0644; return e }, "empty": func(e []entry) []entry { e[1].data = nil; return e }, "wrong MachO": func(e []entry) []entry { e[0].data = plain["arm64"]; return e }, "non MachO": func(e []entry) []entry { e[0].data = []byte("not executable"); return e },
		"oversize notice": func(e []entry) []entry { e[1].data = bytes.Repeat([]byte("x"), MaxNotice+1); return e }, "wrong parent": func(e []entry) []entry { return append(e, entry{"other/", os.ModeDir | 0755, nil, 0, 0}) },
	}
	for n, mutate := range badEntries {
		t.Run(n, func(t *testing.T) {
			if e := CheckArchive(zipBytes(t, mutate(entries("amd64", plain["amd64"]))), "amd64", rev, m.CoreVersion); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Mutate ZIP headers for methods/encryption/oversize claims without allocating huge files.
	for _, kind := range []string{"encryption", "method", "oversize binary", "CRC"} {
		t.Run(kind, func(t *testing.T) {
			z := append([]byte(nil), archives["amd64"]...)
			pos := bytes.Index(z, []byte{'P', 'K', 1, 2})
			switch kind {
			case "encryption":
				binary.LittleEndian.PutUint16(z[pos+8:], binary.LittleEndian.Uint16(z[pos+8:])|1)
			case "method":
				binary.LittleEndian.PutUint16(z[pos+10:], 99)
			case "oversize binary":
				binary.LittleEndian.PutUint32(z[pos+24:], MaxBinary+1)
			case "CRC":
				z[pos+16] ^= 1
			}
			if e := CheckArchive(z, "amd64", rev, m.CoreVersion); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}
