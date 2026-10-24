//go:build ignore

// Run with: go run scripts/build-dist.go
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const wintunURL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
const wintunSHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
const wintunSize = 750540

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return fmt.Errorf("run from the repository root: %w", err)
	}
	version := os.Getenv("BIMERON_VERSION")
	if version == "" {
		if tag, err := exec.Command("git", "describe", "--tags", "--abbrev=0", "--match", "v[0-9]*").Output(); err == nil {
			version = strings.TrimSpace(string(tag)) + "-dev"
		}
	}
	dist := os.Getenv("BIMERON_DIST_DIR")
	if dist == "" {
		dist = filepath.Join(root, "dist")
	}
	mode := "all"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	if len(os.Args) > 2 || (mode != "all" && mode != "windows" && mode != "windows-amd64" && mode != "windows-arm64" && mode != "linux" && mode != "macos") {
		return fmt.Errorf("usage: go run scripts/build-dist.go [all|windows|windows-amd64|windows-arm64|linux|macos]")
	}
	for _, target := range []struct{ os, arch, name string }{
		{"windows", "amd64", "bimeron-windows-amd64.exe"}, {"windows", "arm64", "bimeron-windows-arm64.exe"},
		{"linux", "amd64", "bimeron-linux-amd64"}, {"linux", "arm64", "bimeron-linux-arm64"},
		{"darwin", "amd64", "bimeron-macos-amd64"}, {"darwin", "arm64", "bimeron-macos-arm64"},
	} {
		if mode != "all" && mode != target.os && mode != target.os+"-"+target.arch && !(mode == "macos" && target.os == "darwin") {
			continue
		}
		bin := filepath.Join(root, "bin", target.name)
		if err := os.MkdirAll(filepath.Dir(bin), 0755); err != nil {
			return err
		}
		ldflags := "-s -w"
		if version != "" {
			ldflags += " -X bimeron/core.Version=" + strings.TrimPrefix(version, "v")
		}
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", bin, "./cmd/bimeron")
		cmd.Dir = root
		cmd.Env = append(filteredEnv(), "CGO_ENABLED=0", "GOOS="+target.os, "GOARCH="+target.arch)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		fmt.Printf("Building %s/%s\n", target.os, target.arch)
		if err := cmd.Run(); err != nil {
			return err
		}
		label := target.os
		if label == "darwin" {
			label = "macos"
		}
		out := filepath.Join(dist, label+"-"+target.arch)
		if err := os.MkdirAll(out, 0755); err != nil {
			return err
		}
		exe := "bimeron"
		if target.os == "windows" {
			exe += ".exe"
		}
		for _, pair := range [][2]string{{bin, exe}, {filepath.Join(root, "LICENSE"), "LICENSE"}, {filepath.Join(root, "THIRD_PARTY_NOTICES.txt"), "THIRD_PARTY_NOTICES.txt"}} {
			if err := copyFile(pair[0], filepath.Join(out, pair[1])); err != nil {
				return err
			}
		}
	}
	if mode == "linux" || mode == "macos" {
		return nil
	}
	archive := filepath.Join(root, "bin", "wintun-0.14.1.zip")
	if override := os.Getenv("BIMERON_WINTUN_ARCHIVE"); override != "" {
		archive = override
	}
	if !validArchive(archive) {
		file, err := os.CreateTemp("", "bimeron-wintun-*.zip")
		if err != nil {
			return err
		}
		archive = file.Name()
		file.Close()
		defer os.Remove(archive)
		if err := download(archive); err != nil {
			return err
		}
	}
	if !validArchive(archive) {
		return fmt.Errorf("Wintun archive SHA-256 mismatch")
	}
	z, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer z.Close()
	for _, arch := range []string{"amd64", "arm64"} {
		if strings.HasPrefix(mode, "windows-") && mode != "windows-"+arch {
			continue
		}
		out := filepath.Join(dist, "windows-"+arch)
		for _, pair := range [][2]string{{"wintun/bin/" + arch + "/wintun.dll", "wintun.dll"}, {"wintun/LICENSE.txt", "WINTUN-LICENSE.txt"}} {
			if err := extract(&z.Reader, pair[0], filepath.Join(out, pair[1])); err != nil {
				return err
			}
		}
	}
	fmt.Println("Prepared CLI distributions in dist/.")
	return nil
}

func filteredEnv() []string {
	var env []string
	for _, entry := range os.Environ() {
		key := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
		if key != "GOOS" && key != "GOARCH" && key != "CGO_ENABLED" {
			env = append(env, entry)
		}
	}
	return env
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	return err
}

func validArchive(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == wintunSHA256
}

func download(path string) error {
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	const chunk = 15901
	for start := 0; start < wintunSize; start += chunk {
		end := start + chunk - 1
		if end >= wintunSize {
			end = wintunSize - 1
		}
		var part []byte
		for attempt := 0; attempt < 3; attempt++ {
			part, err = exec.Command("curl", "-L", "--fail", "--silent", "--show-error", "--max-time", "15", "--range", fmt.Sprintf("%d-%d", start, end), wintunURL).Output()
			if err == nil && len(part) == end-start+1 {
				break
			}
			err = fmt.Errorf("Wintun range %d-%d: curl returned %d bytes: %w", start, end, len(part), err)
		}
		if err != nil {
			out.Close()
			return err
		}
		if _, err = out.Write(part); err != nil {
			out.Close()
			return err
		}
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if !validArchive(path) {
		return fmt.Errorf("Wintun download SHA-256 mismatch")
	}
	return nil
}

func extract(z *zip.Reader, name, dst string) error {
	for _, file := range z.File {
		if file.Name != name {
			continue
		}
		in, err := file.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(dst)
		if err != nil {
			in.Close()
			return err
		}
		_, err = io.Copy(out, in)
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
		if closeErr := in.Close(); err == nil {
			err = closeErr
		}
		return err
	}
	return fmt.Errorf("missing Wintun archive entry %s", name)
}
