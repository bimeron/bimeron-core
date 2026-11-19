//go:build ignore

// Usage: go run scripts/check-release-provenance.go -tag vX.Y.Z -dir release -commit <sha>
//
// Checks the build information of every binary in the prepared release ZIPs:
// each CLI executable must come from an unmodified checkout of the release
// commit, built by scripts/build-dist.go for its target; each Android library
// must be a -trimpath gomobile build for its ABI (release/provenance).
package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"bimeron/release/provenance"
)

const (
	maxBinary  = 256 << 20
	maxAndroid = 512 << 20
)

func main() {
	tag := flag.String("tag", "", "release tag")
	dir := flag.String("dir", "release", "directory containing the prepared ZIPs")
	commit := flag.String("commit", "", "release commit")
	flag.Parse()
	if err := run(*tag, *dir, *commit); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(tag, dir, commit string) error {
	if tag == "" || len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" {
		return errors.New("-tag and a full lowercase -commit are required")
	}
	for _, goos := range []string{"linux", "macos", "windows"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			target := goos + "-" + goarch
			binary := "bimeron"
			if goos == "windows" {
				binary += ".exe"
			}
			b, err := zipEntry(filepath.Join(dir, "bimeron-"+tag+"-"+target+".zip"), target+"/"+binary, maxBinary)
			if err != nil {
				return err
			}
			buildOS := goos
			if goos == "macos" {
				buildOS = "darwin"
			}
			if err := provenance.CheckCLIBinary(b, buildOS, goarch, commit); err != nil {
				return fmt.Errorf("%s/%s: %w", target, binary, err)
			}
		}
	}
	aar, err := zipEntry(filepath.Join(dir, "bimeron-"+tag+"-android.zip"), "android/bimeron-core.aar", maxAndroid)
	if err != nil {
		return err
	}
	z, err := zip.NewReader(bytes.NewReader(aar), int64(len(aar)))
	if err != nil {
		return fmt.Errorf("android/bimeron-core.aar: %w", err)
	}
	var abis []string
	for _, f := range z.File {
		if strings.HasSuffix(f.Name, ".so") {
			abis = append(abis, f.Name)
		}
	}
	var want []string
	for abi := range provenance.AndroidABIs {
		want = append(want, "jni/"+abi+"/libgojni.so")
	}
	sort.Strings(abis)
	sort.Strings(want)
	if strings.Join(abis, "\n") != strings.Join(want, "\n") {
		return fmt.Errorf("android/bimeron-core.aar: native libraries %v, want %v", abis, want)
	}
	for abi := range provenance.AndroidABIs {
		name := "jni/" + abi + "/libgojni.so"
		b, err := readEntry(z, name, maxBinary)
		if err != nil {
			return fmt.Errorf("android/bimeron-core.aar: %w", err)
		}
		if err := provenance.CheckAndroidLibrary(b, abi); err != nil {
			return fmt.Errorf("android/bimeron-core.aar %s: %w", name, err)
		}
	}
	fmt.Printf("%s: build provenance verified for commit %s\n", tag, commit)
	return nil
}

func zipEntry(path, name string, limit int64) ([]byte, error) {
	z, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	b, err := readEntry(&z.Reader, name, limit)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return b, nil
}

// readEntry returns the only regular entry called name, refusing duplicates.
func readEntry(z *zip.Reader, name string, limit int64) ([]byte, error) {
	var found *zip.File
	for _, f := range z.File {
		if f.Name == name {
			if found != nil {
				return nil, fmt.Errorf("duplicate entry %s", name)
			}
			found = f
		}
	}
	if found == nil || !found.Mode().IsRegular() {
		return nil, fmt.Errorf("missing regular entry %s", name)
	}
	r, err := found.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("entry %s is larger than %d bytes", name, limit)
	}
	return b, nil
}
