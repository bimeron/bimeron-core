//go:build ignore

// Run with: go run scripts/check-dist.go
package main

import (
	"archive/zip"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

func main() {
	if err := check(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println("Distribution contents verified.")
}

func check() error {
	dist := os.Getenv("BIMERON_DIST_DIR")
	if dist == "" {
		dist = "dist"
	}
	for _, platform := range []string{"windows", "linux", "macos"} {
		for _, arch := range []string{"amd64", "arm64"} {
			dir := filepath.Join(dist, platform+"-"+arch)
			want := []string{"LICENSE", "THIRD_PARTY_NOTICES.txt", "bimeron"}
			if platform == "windows" {
				want = []string{"LICENSE", "THIRD_PARTY_NOTICES.txt", "WINTUN-LICENSE.txt", "bimeron.exe", "wintun.dll"}
			}
			if err := files(dir, want); err != nil {
				return err
			}
			for _, name := range []string{"LICENSE", "THIRD_PARTY_NOTICES.txt"} {
				a, err := digest(filepath.Join(dir, name))
				if err != nil {
					return err
				}
				b, err := digest(name)
				if err != nil {
					return err
				}
				if a != b {
					return fmt.Errorf("%s: %s differs from source", dir, name)
				}
			}
			binary := "bimeron"
			if platform == "windows" {
				binary = "bimeron.exe"
			}
			if err := machine(filepath.Join(dir, binary), platform, arch); err != nil {
				return err
			}
			if platform == "windows" {
				if err := machine(filepath.Join(dir, "wintun.dll"), platform, arch); err != nil {
					return err
				}
				wantDLL := map[string]string{"amd64": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce", "arm64": "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80"}[arch]
				for name, wantHash := range map[string]string{"wintun.dll": wantDLL, "WINTUN-LICENSE.txt": "183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2"} {
					got, err := digest(filepath.Join(dir, name))
					if err != nil {
						return err
					}
					if got != wantHash {
						return fmt.Errorf("%s: %s SHA-256 mismatch", dir, name)
					}
				}
			}
		}
	}
	android := filepath.Join(dist, "android")
	if _, err := os.Stat(android); err == nil {
		if err := files(android, []string{"LICENSE", "THIRD_PARTY_NOTICES.txt", "bimeron-core-sources.jar", "bimeron-core.aar"}); err != nil {
			return err
		}
		z, err := zip.OpenReader(filepath.Join(android, "bimeron-core.aar"))
		if err != nil {
			return err
		}
		defer z.Close()
		var abis []string
		for _, f := range z.File {
			if filepath.Base(f.Name) == "libgojni.so" {
				abis = append(abis, filepath.Base(filepath.Dir(f.Name)))
			}
		}
		slices.Sort(abis)
		if !slices.Equal(abis, []string{"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}) {
			return fmt.Errorf("Android AAR has unexpected ABIs: %v", abis)
		}
	}
	return nil
}

func files(dir string, want []string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var got []string
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		return fmt.Errorf("%s: files %v, want %v", dir, got, want)
	}
	return nil
}

func digest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func machine(path, platform, arch string) error {
	var got string
	switch platform {
	case "windows":
		file, err := pe.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		if file.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
			got = "amd64"
		}
		if file.Machine == pe.IMAGE_FILE_MACHINE_ARM64 {
			got = "arm64"
		}
	case "linux":
		file, err := elf.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		if file.Machine == elf.EM_X86_64 {
			got = "amd64"
		}
		if file.Machine == elf.EM_AARCH64 {
			got = "arm64"
		}
	case "macos":
		file, err := macho.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		if file.Cpu == macho.CpuAmd64 {
			got = "amd64"
		}
		if file.Cpu == macho.CpuArm64 {
			got = "arm64"
		}
	}
	if got != arch {
		return fmt.Errorf("%s: architecture %s, want %s", path, got, arch)
	}
	return nil
}
