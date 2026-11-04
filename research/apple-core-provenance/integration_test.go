package provenance_test

import (
	"archive/tar"
	"archive/zip"
	"bimeron/release/applemanifest"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Explicit opt-in: builds only this repository's source at the local clean commit.
func TestProductionIntegration(t *testing.T) {
	if os.Getenv("BIMERON_APPLE_INTEGRATION") != "1" {
		t.Skip("set BIMERON_APPLE_INTEGRATION=1 for offline real Core builds")
	}
	root, _ := filepath.Abs("../..")
	goexe := filepath.Join(runtime.GOROOT(), "bin", "go")
	git := os.Getenv("BIMERON_TEST_GIT")
	if git == "" {
		var err error
		git, err = exec.LookPath("git")
		if err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(), "PATH="+filepath.Dir(git)+string(os.PathListSeparator)+os.Getenv("PATH"), "GOENV=off", "GOFLAGS=", "GOEXPERIMENT=", "GOAMD64=v1", "GOARM64=v8.0", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOCACHE="+filepath.Join(root, ".tmp/gocache"), "GOTMPDIR="+filepath.Join(root, ".tmp"), "CGO_ENABLED=0")
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
		builder := filepath.Join(dir, ".tmp/builder")
		run(dir, goexe, "build", "-o", builder, "./scripts/build-apple-release.go")
		builderArgs := []string{"-git=" + git, "-go=" + goexe, "-version=0.1.0-beta.1", "-revision=" + rev}
		if i == 0 {
			overlay := filepath.Join(dir, ".tmp/overlay.json")
			replacement := filepath.Join(dir, ".tmp/replacement.go")
			os.WriteFile(replacement, []byte("invalid overlaid source"), 0644)
			data, _ := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(dir, "core/version.go"): replacement}})
			os.WriteFile(overlay, data, 0644)
			for _, flags := range []string{"-overlay=" + overlay, "-tags=unapproved"} {
				c := exec.Command(builder, builderArgs...)
				c.Dir = dir
				c.Env = append(env, "GOFLAGS="+flags)
				if b, e := c.CombinedOutput(); e == nil || !bytes.Contains(b, []byte("GOFLAGS must be empty")) {
					t.Fatalf("ambient flags accepted/wrong failure: %v %s", e, b)
				}
			}
			for _, control := range []struct{ path, output, want string }{
				{filepath.Join(dir, ".tmp/missing-go"), "", "resolve Go"},
				{filepath.Join(dir, ".tmp/wrong-go"), "go version go1.26.8 darwin/arm64", "unsupported compiler"},
				{filepath.Join(dir, ".tmp/wrong-host"), "go version go1.26.9 linux/amd64", "unsupported compiler"},
			} {
				if control.output != "" {
					os.WriteFile(control.path, []byte("#!/bin/sh\necho '"+control.output+"'\n"), 0755)
				}
				c := exec.Command(builder, append(builderArgs, "-go="+control.path)...)
				c.Dir = dir
				c.Env = env
				if b, e := c.CombinedOutput(); e == nil || !bytes.Contains(b, []byte(control.want)) {
					t.Fatalf("tool control: %v %s", e, b)
				}
			}
			c := exec.Command(builder, append(builderArgs, "-git="+filepath.Join(dir, ".tmp/missing-git"))...)
			c.Dir = dir
			c.Env = env
			if b, e := c.CombinedOutput(); e == nil || !bytes.Contains(b, []byte("resolve Git")) {
				t.Fatalf("Git control: %v %s", e, b)
			}
		}
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
				c := exec.Command(builder, append([]string{"-git=" + git, "-go=" + goexe}, args...)...)
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
			c := exec.Command(builder, builderArgs...)
			c.Dir = dir
			c.Env = env
			if b, e := c.CombinedOutput(); e == nil || !bytes.Contains(b, []byte("source must be clean")) {
				t.Fatalf("dirty source accepted/wrong failure: %v %s", e, b)
			}
			os.WriteFile(path, original, 0644)
		} else {
			os.WriteFile(filepath.Join(dir, "core/apple-version.record"), []byte("stale invalid ignored input"), 0644)
		}
		if i == 1 {
			config := filepath.Join(dir, ".tmp/hostile-goenv")
			os.WriteFile(config, []byte("GOFLAGS=-overlay=/nonexistent/overlay.json\nGOEXPERIMENT=invalid\n"), 0644)
			cleanEnv := env
			env = append(env, "GOENV="+config, "GOEXPERIMENT=invalid", "GOAMD64=v4", "GOARM64=v9.5", "GOTOOLDIR=/nonexistent", "GOROOT=/nonexistent", "GOOS=linux", "GOARCH=386")
			run(dir, builder, builderArgs...)
			env = cleanEnv
		} else {
			run(dir, builder, builderArgs...)
		}
		current := map[string][]byte{}
		for _, arch := range []string{"amd64", "arm64"} {
			b, e := os.ReadFile(filepath.Join(dir, ".tmp/apple-release/bimeron-v0.1.0-beta.1-macos-"+arch+".zip"))
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
		// Public identifier only: unsigned preparation must preserve shipping review=false.
		pub := bytes.Repeat([]byte{0x42}, 32)
		data := run(dir, goexe, "run", "./scripts/apple-release-manifest.go",
			"-dir=.tmp/apple-release", "-tag=v0.1.0-beta.1", "-revision="+rev,
			"-public-key="+base64.StdEncoding.EncodeToString(pub), "-compat=release/apple-compatibility.json")
		manifest, err := applemanifest.Parse(data)
		if err != nil {
			t.Fatal("unsigned preparer output", err)
		}
		policyBytes, err := os.ReadFile(filepath.Join(dir, "release/apple-compatibility.json"))
		if err != nil {
			t.Fatal(err)
		}
		policy, err := applemanifest.ParseCompatibility(policyBytes)
		if err != nil || policy.AppleReviewed || manifest.Compatibility != policy ||
			manifest.Tag != "v0.1.0-beta.1" || manifest.CoreVersion != "0.1.0-beta.1" ||
			manifest.SourceRevision != rev || manifest.KeyID != applemanifest.KeyID(pub) {
			t.Fatalf("unsigned preparation identity/policy mismatch: %+v (%v)", manifest, err)
		}
		for _, a := range manifest.Archives {
			b := current[a.Arch]
			if a.Name != "bimeron-v0.1.0-beta.1-macos-"+a.Arch+".zip" ||
				a.Size != int64(len(b)) || a.SHA256 != fmt.Sprintf("%x", sha256.Sum256(b)) {
				t.Fatalf("preparer archive identity mismatch: %+v", a)
			}
		}
		t.Logf("unsigned preparer handoff passed: both archive names/hashes, original review=false policy, synthetic public identifier only")
		if i == 0 {
			host := filepath.Join(dir, ".tmp/apple-release/bimeron-"+runtime.GOARCH)
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
			zr, e := zip.NewReader(bytes.NewReader(current[runtime.GOARCH]), int64(len(current[runtime.GOARCH])))
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
			if e = applemanifest.CheckArchive(zipOut.Bytes(), runtime.GOARCH, rev, "0.1.0-beta.1"); e != nil {
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
