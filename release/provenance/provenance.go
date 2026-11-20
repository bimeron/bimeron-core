// Package provenance checks the build information embedded in release binaries.
package provenance

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
)

// AndroidABIs maps each Android ABI directory of the AAR to its GOARCH.
var AndroidABIs = map[string]string{
	"arm64-v8a":   "arm64",
	"armeabi-v7a": "arm",
	"x86":         "386",
	"x86_64":      "amd64",
}

// defaultArchLevel is the architecture feature setting Go records for each
// GOARCH, at the value used for releases. A different level would raise the
// minimum CPU the package runs on.
var defaultArchLevel = map[string][2]string{
	"amd64": {"GOAMD64", "v1"},
	"arm64": {"GOARM64", "v8.0"},
	"arm":   {"GOARM", "7"},
	"386":   {"GO386", "sse2"},
}

// Settings that may appear with any value. Every other recorded setting must
// match the release recipe exactly, so extra flags (for example -tags,
// -gcflags, -race or GOEXPERIMENT, also when they come from GOFLAGS) and
// -ldflags, which Go records only without -trimpath, are refused.
var optionalSettings = map[string]bool{"vcs.time": true, "DefaultGODEBUG": true}

// CheckCLIBinary verifies that a packaged CLI executable was built by
// scripts/build-dist.go from an unmodified checkout of revision: Go records
// vcs.revision and vcs.modified=false, -trimpath, CGO_ENABLED=0 and the target
// GOOS/GOARCH, and the executable format matches the target.
func CheckCLIBinary(b []byte, goos, goarch, revision string) error {
	return checkCLIBinary(b, goos, goarch, revision, "bimeron/cmd/bimeron", "bimeron")
}

func checkCLIBinary(b []byte, goos, goarch, revision, path, module string) error {
	if revision == "" {
		return errors.New("missing expected revision")
	}
	if err := checkExecutable(b, goos, goarch); err != nil {
		return err
	}
	info, err := buildinfo.Read(bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("read build information: %w", err)
	}
	if info.Path != path || info.Main.Path != module {
		return fmt.Errorf("unexpected main package %q in module %q", info.Path, info.Main.Path)
	}
	want := map[string]string{
		"-buildmode": "exe", "-compiler": "gc", "-trimpath": "true", "CGO_ENABLED": "0",
		"GOOS": goos, "GOARCH": goarch,
		"vcs": "git", "vcs.revision": revision, "vcs.modified": "false",
	}
	return checkSettings(info, goarch, want)
}

// CheckAndroidLibrary verifies one libgojni.so of the Android AAR: a gomobile
// c-shared library for the ABI's GOARCH, built with -trimpath and no extra
// build flags. gomobile builds from a generated module, so Go records no VCS
// revision for it.
func CheckAndroidLibrary(b []byte, abi string) error {
	goarch, ok := AndroidABIs[abi]
	if !ok {
		return fmt.Errorf("unknown Android ABI %q", abi)
	}
	if err := checkExecutable(b, "android", goarch); err != nil {
		return err
	}
	info, err := buildinfo.Read(bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("read build information: %w", err)
	}
	return checkAndroidInfo(info, goarch)
}

// AndroidSourceLink is the fixed path through which scripts/build-android.sh
// builds. gomobile records the absolute directory of every locally replaced
// module, so a library built elsewhere would name a directory of the build
// machine. scripts/build-android.ps1 builds from the root of a temporary
// drive letter instead.
const AndroidSourceLink = "/tmp/bimeron-core-android/src"

func checkAndroidInfo(info *debug.BuildInfo, goarch string) error {
	if info.Path != "gobind/gobind" || !hasDep(info, "bimeron") {
		return fmt.Errorf("unexpected main package %q", info.Path)
	}
	if err := checkAndroidReplacements(info); err != nil {
		return err
	}
	want := map[string]string{
		"-buildmode": "c-shared", "-compiler": "gc", "-trimpath": "true", "CGO_ENABLED": "1",
		"GOOS": "android", "GOARCH": goarch,
	}
	return checkSettings(info, goarch, want)
}

// checkAndroidReplacements requires every module replaced by a directory to
// lie under the fixed source path, so the library names no local directory.
func checkAndroidReplacements(info *debug.BuildInfo) error {
	root := ""
	for _, d := range info.Deps {
		if d.Path == "bimeron" && d.Replace != nil {
			root = d.Replace.Path
		}
	}
	drive := len(root) == 3 && root[0] >= 'A' && root[0] <= 'Z' && root[1:] == ":\\"
	if root != AndroidSourceLink && !drive {
		return fmt.Errorf("module bimeron was built from %q, not from %s or a drive root", root, AndroidSourceLink)
	}
	sep := "/"
	if drive {
		sep = ""
	}
	for _, d := range info.Deps {
		// Go reports a directory replacement with version "(devel)".
		if r := d.Replace; r != nil && (r.Version == "" || r.Version == "(devel)") && r.Path != root && !strings.HasPrefix(r.Path, root+sep) {
			return fmt.Errorf("module %s was built from %q, outside %s", d.Path, r.Path, root)
		}
	}
	return nil
}

func hasDep(info *debug.BuildInfo, path string) bool {
	for _, d := range info.Deps {
		if d.Path == path {
			return true
		}
	}
	return false
}

func checkSettings(info *debug.BuildInfo, goarch string, want map[string]string) error {
	level, ok := defaultArchLevel[goarch]
	if !ok {
		return fmt.Errorf("unsupported GOARCH %q", goarch)
	}
	want[level[0]] = level[1]
	got := map[string]string{}
	for _, s := range info.Settings {
		if _, dup := got[s.Key]; dup {
			return fmt.Errorf("duplicate build setting %s", s.Key)
		}
		got[s.Key] = s.Value
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	// Report the target first: a wrong GOOS or GOARCH explains the rest.
	sort.Slice(keys, func(i, j int) bool {
		ri, rj := settingRank(keys[i]), settingRank(keys[j])
		if ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		if v, ok := got[k]; !ok || v != want[k] {
			return fmt.Errorf("build setting %s is %q, want %q", k, v, want[k])
		}
	}
	for _, s := range info.Settings {
		if _, ok := want[s.Key]; !ok && !optionalSettings[s.Key] {
			return fmt.Errorf("unexpected build setting %s", s.Key)
		}
	}
	return nil
}

func settingRank(key string) int {
	switch key {
	case "GOOS":
		return 0
	case "GOARCH":
		return 1
	}
	return 2
}

func checkExecutable(b []byte, goos, goarch string) error {
	r := bytes.NewReader(b)
	switch goos {
	case "linux", "android":
		f, err := elf.NewFile(r)
		if err != nil {
			return err
		}
		defer f.Close()
		machine := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64, "arm": elf.EM_ARM, "386": elf.EM_386}[goarch]
		kind := elf.ET_EXEC
		if goos == "android" {
			kind = elf.ET_DYN
		}
		if machine == elf.EM_NONE || f.Machine != machine || (f.Type != kind && !(goos == "linux" && f.Type == elf.ET_DYN)) {
			return fmt.Errorf("ELF file is not a %s/%s %s", goos, goarch, kind)
		}
	case "windows":
		f, err := pe.NewFile(r)
		if err != nil {
			return err
		}
		defer f.Close()
		machine := map[string]uint16{"amd64": pe.IMAGE_FILE_MACHINE_AMD64, "arm64": pe.IMAGE_FILE_MACHINE_ARM64}[goarch]
		c := f.FileHeader.Characteristics
		if machine == 0 || f.FileHeader.Machine != machine || c&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 || c&pe.IMAGE_FILE_DLL != 0 {
			return fmt.Errorf("PE file is not a windows/%s executable", goarch)
		}
	case "darwin":
		f, err := macho.NewFile(r)
		if err != nil {
			return err
		}
		defer f.Close()
		cpu := map[string]macho.Cpu{"amd64": macho.CpuAmd64, "arm64": macho.CpuArm64}[goarch]
		if cpu == 0 || f.Cpu != cpu || f.Type != macho.TypeExec {
			return fmt.Errorf("Mach-O file is not a darwin/%s executable", goarch)
		}
	default:
		return fmt.Errorf("unsupported GOOS %q", goos)
	}
	return nil
}
