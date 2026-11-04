package provenance_test

import (
	"archive/tar"
	"archive/zip"
	"bimeron/release/applemanifest"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Explicit opt-in: builds only this repository's source at the local clean commit.
func TestProductionIntegration(t *testing.T) {
	if os.Getenv("BIMERON_APPLE_INTEGRATION") != "1" {
		t.Skip("set BIMERON_APPLE_INTEGRATION=1 for offline real Core builds")
	}
	root, _ := filepath.Abs("../..")
	goexe := "<LOCAL_HOME>/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.darwin-arm64/bin/go"
	git := "<LOCAL_HOME>/.local/bin/git"
	env := append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOCACHE="+filepath.Join(root, ".tmp/gocache"), "GOTMPDIR="+filepath.Join(root, ".tmp"), "CGO_ENABLED=0")
	run := func(dir, exe string, args ...string) []byte {
		t.Helper()
		c := exec.Command(exe, args...)
		c.Dir = dir
		c.Env = env
		b, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %v\n%s", exe, args, e, b)
		}
		return b
	}
	rev := strings.TrimSpace(string(run(root, git, "rev-parse", "HEAD")))
	archive := run(root, git, "archive", "HEAD")
	var first map[string][]byte
	for i := 0; i < 2; i++ {
		dir := t.TempDir()
		r := tar.NewReader(bytes.NewReader(archive))
		for {
			h, e := r.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			if h.Typeflag == tar.TypeXGlobalHeader {
				continue
			}
			path := filepath.Join(dir, h.Name)
			if h.Typeflag == tar.TypeDir {
				os.MkdirAll(path, 0755)
				continue
			}
			if h.Typeflag != tar.TypeReg {
				t.Fatalf("unsupported source entry %s", h.Name)
			}
			os.MkdirAll(filepath.Dir(path), 0755)
			b, e := io.ReadAll(r)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(path, b, os.FileMode(h.Mode)); e != nil {
				t.Fatal(e)
			}
		}
		run(dir, git, "init", "-q")
		// Reuse exact commit identity and tree without contacting any remote.
		run(dir, git, "fetch", "--no-tags", root, rev)
		run(dir, git, "reset", "--hard", rev)
		// Missing embed and unsupported OS fail closed before generation.
		if i == 0 {
			for _, goos := range []string{"darwin", "linux"} {
				c := exec.Command(goexe, "build", "-tags=bimeron_apple_release", "-o", filepath.Join(dir, ".tmp/missing"), "./cmd/bimeron")
				c.Dir = dir
				c.Env = append(env, "GOOS="+goos)
				b, e := c.CombinedOutput()
				if e == nil {
					t.Fatal("missing/unsupported record build accepted")
				}
				t.Logf("expected %s rejection: %s", goos, b)
			}
		}

		if i == 0 {
			for _, args := range [][]string{{"-version=1.2.3+bad", "-revision=" + rev}, {"-version=1.2.3", "-revision=" + strings.Repeat("0", 40)}} {
				c := exec.Command(goexe, append([]string{"run", "./scripts/build-apple-release.go"}, args...)...)
				c.Dir = dir
				c.Env = env
				if b, e := c.CombinedOutput(); e == nil {
					t.Fatalf("builder accepted %v: %s", args, b)
				}
			}
			path := filepath.Join(dir, "core/version.go")
			original, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			os.WriteFile(path, append(original, []byte("\n// dirty control\n")...), 0644)
			c := exec.Command(goexe, "run", "./scripts/build-apple-release.go", "-version=0.1.0-beta.1", "-revision="+rev)
			c.Dir = dir
			c.Env = env
			if b, e := c.CombinedOutput(); e == nil || !bytes.Contains(b, []byte("source must be clean")) {
				t.Fatalf("dirty source accepted/wrong failure: %v %s", e, b)
			}
			os.WriteFile(path, original, 0644)
		} else {
			os.WriteFile(filepath.Join(dir, "core/apple-version.record"), []byte("stale invalid ignored input"), 0644)
		}
		run(dir, goexe, "run", "./scripts/build-apple-release.go", "-version=0.1.0-beta.1", "-revision="+rev)
		current := map[string][]byte{}
		for _, arch := range []string{"amd64", "arm64"} {
			b, e := os.ReadFile(filepath.Join(dir, ".tmp/apple-release/macos-"+arch+".zip"))
			if e != nil {
				t.Fatal(e)
			}
			if e = applemanifest.CheckArchive(b, arch, rev, "0.1.0-beta.1"); e != nil {
				t.Fatal(e)
			}
			current[arch] = b
			t.Logf("%s archive sha256 %x", arch, sha256.Sum256(b))
			if i == 1 && !bytes.Equal(first[arch], b) {
				t.Fatal("path-dependent output", arch)
			}
		}
		if i == 0 {
			host := filepath.Join(dir, ".tmp/apple-release/bimeron-arm64")
			var info struct {
				Version string `json:"version"`
			}
			if e := json.Unmarshal(run(dir, host, "version"), &info); e != nil || info.Version != "0.1.0-beta.1" {
				t.Fatal(info, e)
			}
			override := filepath.Join(dir, ".tmp/override")
			run(dir, goexe, "build", "-trimpath", "-buildvcs=true", "-tags=bimeron_apple_release", "-ldflags=-s -w -X bimeron/core.Version=9.9.9 -X bimeron/core.Nonexistent=8.8.8", "-o", override, "./cmd/bimeron")
			if e := json.Unmarshal(run(dir, override, "version"), &info); e != nil || info.Version != "0.1.0-beta.1" {
				t.Fatal("Apple override", info, e)
			}

			overrideBytes, e := os.ReadFile(override)
			if e != nil {
				t.Fatal(e)
			}
			zr, e := zip.NewReader(bytes.NewReader(current["arm64"]), int64(len(current["arm64"])))
			if e != nil {
				t.Fatal(e)
			}
			var zipOut bytes.Buffer
			zw := zip.NewWriter(&zipOut)
			for _, f := range zr.File {
				r, e := f.Open()
				if e != nil {
					t.Fatal(e)
				}
				b, e := io.ReadAll(r)
				r.Close()
				if e != nil {
					t.Fatal(e)
				}
				if strings.HasSuffix(f.Name, "/bimeron") {
					b = overrideBytes
				}
				h := f.FileHeader
				w, e := zw.CreateHeader(&h)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = w.Write(b); e != nil {
					t.Fatal(e)
				}
			}
			if e = zw.Close(); e != nil {
				t.Fatal(e)
			}
			if e = applemanifest.CheckArchive(zipOut.Bytes(), "arm64", rev, "0.1.0-beta.1"); e != nil {
				t.Fatal("override static check", e)
			}
			legacy := filepath.Join(dir, ".tmp/legacy")
			run(dir, goexe, "build", "-trimpath", "-ldflags=-s -w -X bimeron/core.Version=7.8.9", "-o", legacy, "./cmd/bimeron")
			if e := json.Unmarshal(run(dir, legacy, "version"), &info); e != nil || info.Version != "7.8.9" {
				t.Fatal("legacy override", info, e)
			}
		}
		first = current
	}
}
