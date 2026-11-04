package prototype

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRecords(t *testing.T) {
	good, _ := Frame("1.2.3-beta.1")
	if v, e := Parse(good); e != nil || v != "1.2.3-beta.1" {
		t.Fatal(v, e)
	}
	controls := map[string][]byte{"build suffix": []byte(Prefix + "011:1.2.3+local" + suffix), "missing": []byte("other data"), "duplicate": append(append([]byte{}, good...), good...), "truncated": good[:len(good)-1], "malformed": []byte(Prefix + "003:abc" + suffix), "oversized": []byte(Prefix + "129:" + strings.Repeat("a", 129) + suffix), "bad length": []byte(Prefix + "xx3:1.2" + suffix), "bad terminator": bytes.ReplaceAll(good, []byte("END."), []byte("BAD.")), "partial marker": []byte("BIMERON.APPLE.CORE.VERSION/v1"), "leading zero": []byte(Prefix + "010:1.2.3-01.1" + suffix)}
	for name, data := range controls {
		t.Run(name, func(t *testing.T) {
			if _, e := Parse(data); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, e := Parse(make([]byte, MaxSection+1)); e == nil {
		t.Fatal("accepted oversized section")
	}
	for _, v := range []string{"01.2.3", "1.2.3-01", "1.2", "1.2.3-", "1.2.3+", "1.2.3+local"} {
		if _, e := Frame(v); e == nil {
			t.Fatal(v)
		}
	}
}

func TestFileBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized")
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(MaxFile + 1); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	if e = Verify(path, Expected{}); e == nil || e.Error() != "invalid file size or type" {
		t.Fatal(e)
	}
	if e = Verify(t.TempDir(), Expected{}); e == nil || e.Error() != "invalid file size or type" {
		t.Fatal(e)
	}
}

//go:embed testdata/main.go.txt
var cliSource string

func TestOfflineHarness(t *testing.T) {
	root, err := filepath.Abs(".scratch")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(os.MkdirAll(root, 0755))
	cache := filepath.Join(root, "cache")
	must(os.MkdirAll(cache, 0755))
	env := append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOCACHE="+cache, "GOMODCACHE="+filepath.Join(root, "modcache"), "GOTMPDIR="+root, "GOWORK=off", "GOFLAGS=")
	run := func(dir, bin string, args ...string) string {
		t.Helper()
		c := exec.Command(bin, args...)
		c.Dir = dir
		c.Env = env
		b, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %v\n%s", bin, args, e, b)
		}
		return strings.TrimSpace(string(b))
	}
	git := "/Users/wrk/.local/bin/git"
	a := filepath.Join(root, "checkout-a")
	b := filepath.Join(root, "different-path-b")
	must(os.MkdirAll(a, 0755))
	write := func(dir, name, content string) { must(os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)) }
	write(a, "go.mod", "module synthetic.local/core\n\ngo 1.26\n")
	write(a, "main.go", cliSource)
	write(a, ".gitignore", "version.record\n")
	run(a, git, "init", "-q")
	run(a, git, "config", "user.name", "solarcadence")
	run(a, git, "config", "user.email", "solarcadence@localhost")
	run(a, git, "add", ".")
	run(a, git, "commit", "-qm", "test: synthetic offline fixture")
	revision := run(a, git, "rev-parse", "HEAD")
	must(os.CopyFS(b, os.DirFS(a)))
	framed, err := os.ReadFile("testdata/version.record")
	must(err)
	if v, e := Parse(framed); e != nil || v != "1.2.3-beta.1" {
		t.Fatal(v, e)
	}
	write(a, "version.record", string(framed))
	write(b, "version.record", string(framed))
	build := func(dir, arch, name string, extra ...string) string {
		t.Helper()
		out := filepath.Join(root, name)
		args := []string{"build", "-buildvcs=true", "-trimpath", "-ldflags", "-s -w " + strings.Join(extra, " "), "-o", out, "."}
		c := exec.Command("go", args...)
		c.Dir = dir
		c.Env = append(env, "GOOS=darwin", "GOARCH="+arch)
		if data, e := c.CombinedOutput(); e != nil {
			t.Fatalf("build: %v %s", e, data)
		}
		return out
	}
	digest := func(path string) [32]byte { data, e := os.ReadFile(path); must(e); return sha256.Sum256(data) }
	results := map[string]any{"go": run(root, "go", "version"), "revision": revision, "host": runtime.GOOS + "/" + runtime.GOARCH, "runtime_arches": []string{runtime.GOARCH}, "flags": "-buildvcs=true -trimpath -ldflags '-s -w'", "ignored_generation_clean": run(a, git, "status", "--porcelain") == ""}
	for _, arch := range []string{"arm64", "amd64"} {
		x := build(a, arch, arch+"-a")
		y := build(b, arch, arch+"-b")
		h := digest(x)
		if h != digest(y) {
			t.Fatal("path-dependent binary", arch)
		}
		data, e := os.ReadFile(x)
		must(e)
		for _, path := range []string{a, b} {
			if bytes.Contains(data, []byte(path)) {
				t.Fatal("checkout path retained")
			}
		}
		want := Expected{"1.2.3-beta.1", revision, arch, h}
		must(Verify(x, want))
		for _, kind := range []string{"version", "revision", "arch", "hash"} {
			bad := want
			switch kind {
			case "version":
				bad.Version = "9.9.9"
			case "revision":
				bad.Revision = strings.Repeat("0", 40)
			case "arch":
				if arch == "arm64" {
					bad.Arch = "amd64"
				} else {
					bad.Arch = "arm64"
				}
			case "hash":
				bad.SHA256[0] ^= 1
			}
			if Verify(x, bad) == nil {
				t.Fatal("accepted wrong", kind)
			}
		}
		fake := build(a, arch, arch+"-fake-x", "-X missing.local/core.Version=9.9.9")
		fw := want
		fw.SHA256 = digest(fake)
		must(Verify(fake, fw))
		if runtime.GOOS == "darwin" && runtime.GOARCH == arch {
			if got := run(root, x); got != want.Version {
				t.Fatal(got)
			}
			if got := run(root, fake); got != want.Version {
				t.Fatal("fake -X changed CLI", got)
			}
		}
		results[arch] = fmt.Sprintf("%x", h)
	}
	// Missing VCS and wrong OS are independent rejection controls.
	for _, control := range []string{"missing-vcs", "wrong-os"} {
		out := filepath.Join(root, control)
		args := []string{"build", "-trimpath", "-ldflags", "-s -w", "-o", out, "."}
		goos := "darwin"
		if control == "missing-vcs" {
			args = append([]string{"build", "-buildvcs=false"}, args[1:]...)
		} else {
			goos = "linux"
		}
		c := exec.Command("go", args...)
		c.Dir = a
		c.Env = append(env, "GOOS="+goos, "GOARCH=arm64")
		if data, e := c.CombinedOutput(); e != nil {
			t.Fatalf("%s: %v %s", control, e, data)
		}
		if Verify(out, Expected{"1.2.3-beta.1", revision, "arm64", digest(out)}) == nil {
			t.Fatal("accepted", control)
		}
	}
	for _, arch := range []string{"arm64", "amd64"} {
		// A valid frame elsewhere in the file cannot replace the allowed-section record.
		original, e := os.ReadFile(filepath.Join(root, arch+"-a"))
		must(e)
		mf, e := macho.NewFile(bytes.NewReader(original))
		must(e)
		section := mf.Section("__rodata")
		if section == nil || section.Seg != "__TEXT" {
			t.Fatal("missing allowed rodata")
		}
		start, end := int(section.Offset), int(section.Offset+uint32(section.Size))
		at := start + bytes.Index(original[start:end], framed)
		if at < start {
			t.Fatal("record absent")
		}
		for _, control := range []string{"missing", "malformed", "duplicate", "truncated", "oversized", "unrelated"} {
			data := append([]byte{}, original...)
			switch control {
			case "missing":
				data[at] = 'x'
			case "malformed":
				data[at+len(Prefix)] = 'x'
			case "oversized":
				copy(data[at+len(Prefix):], "129")
			case "truncated":
				copy(data[at+len(framed)-5:], "xxxxx")
			case "duplicate":
				duplicateAt := start
				if duplicateAt+len(framed) > at {
					duplicateAt = at + len(framed)
				}
				if duplicateAt+len(framed) > end {
					t.Fatal("no room for duplicate in rodata")
				}
				copy(data[duplicateAt:], framed)
				if bytes.Count(data[start:end], []byte(Prefix)) != 2 {
					t.Fatal("duplicate not in allowed rodata")
				}
			case "unrelated":
				data[at] = 'x'
				data = append(data, framed...)
			}
			path := filepath.Join(root, arch+"-record-"+control)
			must(os.WriteFile(path, data, 0644))
			if e := Verify(path, Expected{"1.2.3-beta.1", revision, arch, sha256.Sum256(original)}); e == nil || e.Error() != "hash mismatch" {
				t.Fatal("tampering did not fail before parsing", e)
			}
			if Verify(path, Expected{"1.2.3-beta.1", revision, arch, digest(path)}) == nil {
				t.Fatal("accepted binary control", control)
			}
		}
		// Section size is rejected before section data is allocated or read.
		oversizedSection := append([]byte{}, original...)
		header := bytes.Index(oversizedSection, append([]byte("__rodata"), make([]byte, 8)...))
		if header < 0 {
			t.Fatal("section header absent")
		}
		binary.LittleEndian.PutUint64(oversizedSection[header+40:header+48], MaxSection+1)
		sectionPath := filepath.Join(root, arch+"-oversized-section")
		must(os.WriteFile(sectionPath, oversizedSection, 0644))
		if e := Verify(sectionPath, Expected{"1.2.3-beta.1", revision, arch, digest(sectionPath)}); e == nil || e.Error() != "invalid record section" {
			t.Fatal("section bounds", e)
		}
		// Same-length build-info mutations retain a valid Mach-O and isolate setting checks.
		for _, mutation := range []struct{ old, new, key string }{
			{"GOOS=darwin", "GOOS=linuxx", "GOOS"},
			{"GOARCH=" + arch, "GOARCH=xxxxx", "GOARCH"},
			{"GOARCH=" + arch, "XXXXXX=" + arch, "GOARCH"},
			{"vcs.revision=" + revision, "xxx.revision=" + revision, "vcs.revision"},
			{"vcs.revision=" + revision, "vcs.revision=" + strings.Repeat("0", len(revision)), "vcs.revision"},
		} {
			if bytes.Count(original, []byte(mutation.old)) < 1 {
				t.Fatal("setting absent", mutation.old)
			}
			data := bytes.ReplaceAll(original, []byte(mutation.old), []byte(mutation.new))
			path := filepath.Join(root, arch+"-setting-"+mutation.key)
			must(os.WriteFile(path, data, 0644))
			want := Expected{"1.2.3-beta.1", revision, arch, sha256.Sum256(original)}
			if e := Verify(path, want); e == nil || e.Error() != "hash mismatch" {
				t.Fatal("setting mutation bypassed hash", e)
			}
			want.SHA256 = sha256.Sum256(data)
			if e := Verify(path, want); e == nil || !strings.Contains(e.Error(), "build setting "+mutation.key+" mismatch") {
				t.Fatal("wrong setting rejection", e)
			}
		}
	}
	// Ignored generated bytes can change the claimed version without dirtying Git.
	changed, err := Frame("2.0.0")
	must(err)
	write(a, "version.record", string(changed))
	if run(a, git, "status", "--porcelain") != "" {
		t.Fatal("generation dirtied tree")
	}
	generated := build(a, runtime.GOARCH, "ignored-change")
	must(Verify(generated, Expected{"2.0.0", revision, runtime.GOARCH, digest(generated)}))
	if runtime.GOOS == "darwin" {
		if got := run(root, generated); got != "2.0.0" {
			t.Fatal("changed CLI", got)
		}
	}
	// Source-built CLI framing controls must fail with the explicit parser panic.
	for name, record := range map[string]string{"truncated": "x", "malformed": Prefix + "+05:1.2.3" + suffix, "oversized": Prefix + "129:" + strings.Repeat("a", 129) + suffix, "trailing": string(changed) + "x"} {
		write(a, "version.record", record)
		out := build(a, runtime.GOARCH, "cli-"+name)
		if runtime.GOOS == "darwin" {
			c := exec.Command(out)
			output, e := c.CombinedOutput()
			if e == nil || !bytes.Contains(output, []byte("panic:")) || bytes.Contains(output, []byte("runtime error")) {
				t.Fatalf("CLI control %s: %v %s", name, e, output)
			}
		}
	}
	write(a, "version.record", string(changed))
	write(a, "main.go", cliSource+"\n// tracked dirty control\n")
	dirty := build(a, "arm64", "dirty")
	if Verify(dirty, Expected{"2.0.0", revision, "arm64", digest(dirty)}) == nil {
		t.Fatal("accepted dirty source")
	}
	// A marker in a writable section is not accepted as provenance.
	decoy := strings.Replace(cliSource, "var record string", "var record []byte", 1)
	decoy = strings.Replace(decoy, "func Version() string {", "func Version() string {\n record := string(record)", 1)
	write(b, "main.go", decoy)
	run(b, git, "config", "user.name", "solarcadence")
	run(b, git, "config", "user.email", "solarcadence@localhost")
	run(b, git, "add", "main.go")
	run(b, git, "commit", "-qm", "test: writable marker control")
	decoyRev := run(b, git, "rev-parse", "HEAD")
	d := build(b, "arm64", "decoy")
	if Verify(d, Expected{"1.2.3-beta.1", decoyRev, "arm64", digest(d)}) == nil {
		t.Fatal("accepted writable marker")
	}
	results["host_cli_assertions"] = "original record; nonexistent -X retains original; changed ignored record reports 2.0.0; malformed/truncated/oversized/trailing frames panic explicitly"
	results["file_bounds"] = "regular files only; 256 MiB maximum with growth-limited reads; sparse oversized-file and directory rejection tested"
	results["signature_verification"] = "not implemented or tested; harness-computed digest provides no authenticity"
	results["negative_controls"] = "both CPUs: binary record mutations (duplicate asserted in allowed rodata), oversized section, hash-first OS/GOARCH/revision setting mutations, wrong expected version/revision/CPU/hash; ELF rejection; missing VCS; dirty source; writable marker; host CLI framing failures"
	encoded, e := json.MarshalIndent(results, "", "  ")
	must(e)
	must(os.WriteFile("results.json", append(encoded, '\n'), 0644))
}
