//go:build ignore

// Standalone offline Apple builder. Run from the repository root.
package main

import (
	"archive/zip"
	"bimeron/internal/appleversion"
	"bimeron/release/applemanifest"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	version := flag.String("version", "", "explicit approved exact version")
	revision := flag.String("revision", "", "explicit approved full source revision")
	out := flag.String("out", ".tmp/apple-release", "local output directory")
	flag.Parse()
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	for _, pair := range [][2]string{{"GOCACHE", filepath.Join(root, ".tmp/gocache")}, {"GOTMPDIR", filepath.Join(root, ".tmp")}, {"TMPDIR", filepath.Join(root, ".tmp")}} {
		if err := os.MkdirAll(pair[1], 0755); err != nil {
			return err
		}
		if err := os.Setenv(pair[0], pair[1]); err != nil {
			return err
		}
	}

	if !appleversion.ValidVersion(*version) || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(*revision) || flag.NArg() != 0 {
		return fmt.Errorf("explicit canonical version and full approved revision required")
	}
	git := "/Users/wrk/.local/bin/git"
	command := func(exe string, args ...string) ([]byte, error) {
		c := exec.Command(exe, args...)
		c.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOWORK=off")
		b, e := c.CombinedOutput()
		if e != nil {
			return nil, fmt.Errorf("%s: %w: %s", exe, e, b)
		}
		return b, nil
	}
	head, e := command(git, "rev-parse", "HEAD")
	if e != nil {
		return e
	}
	if string(bytes.TrimSpace(head)) != *revision {
		return fmt.Errorf("approved revision differs from HEAD")
	}
	status, e := command(git, "status", "--porcelain", "--untracked-files=normal")
	if e != nil {
		return e
	}
	if len(status) != 0 {
		return fmt.Errorf("source must be clean: %s", status)
	}
	record, e := appleversion.Frame(*version)
	if e != nil {
		return e
	}
	if e = os.WriteFile("core/apple-version.record", record, 0644); e != nil {
		return e
	}
	actual, e := os.ReadFile("core/apple-version.record")
	if e != nil {
		return e
	}
	if !bytes.Equal(actual, record) {
		return fmt.Errorf("generated input differs")
	}
	if e = os.MkdirAll(*out, 0755); e != nil {
		return e
	}
	goexe := "/Users/wrk/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.darwin-arm64/bin/go"
	for _, arch := range []string{"amd64", "arm64"} {
		binary := filepath.Join(*out, "bimeron-"+arch)
		c := exec.Command(goexe, "build", "-trimpath", "-buildvcs=true", "-tags=bimeron_apple_release", "-ldflags=-s -w", "-o", binary, "./cmd/bimeron")
		c.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOWORK=off", "CGO_ENABLED=0", "GOOS=darwin", "GOARCH="+arch)
		if b, e := c.CombinedOutput(); e != nil {
			return fmt.Errorf("build %s: %w: %s", arch, e, b)
		}
		var archive bytes.Buffer
		z := zip.NewWriter(&archive)
		for _, name := range []string{"bimeron", "LICENSE", "THIRD_PARTY_NOTICES.txt"} {
			path := name
			if name == "bimeron" {
				path = binary
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			h := &zip.FileHeader{Name: "macos-" + arch + "/" + name, Method: zip.Deflate}
			h.SetMode(0644)
			if name == "bimeron" {
				h.SetMode(0755)
			}
			w, e := z.CreateHeader(h)
			if e != nil {
				return e
			}
			if _, e = w.Write(b); e != nil {
				return e
			}
		}
		if e = z.Close(); e != nil {
			return e
		}
		if e = applemanifest.CheckArchive(archive.Bytes(), arch, *revision, *version); e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(*out, "macos-"+arch+".zip"), archive.Bytes(), 0644); e != nil {
			return e
		}
	}
	fmt.Printf("Validated explicit additional record input: %x\n", record)
	return nil
}
