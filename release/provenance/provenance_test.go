package provenance

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

type fixtureRepo struct {
	dir, git, rev string
}

func newFixtureRepo(t *testing.T) fixtureRepo {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not available")
	}
	r := fixtureRepo{dir: t.TempDir(), git: git}
	for name, body := range map[string]string{
		"go.mod":  "module fixture\n\ngo 1.26\n",
		"main.go": "package main\n\nfunc main() { println(\"fixture\") }\n",
	} {
		if err := os.WriteFile(filepath.Join(r.dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	r.run(t, "init", "-q")
	r.run(t, "add", ".")
	r.run(t, "-c", "user.name=Synthetic Test", "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "test: synthetic build fixture")
	r.rev = r.run(t, "rev-parse", "HEAD")
	return r
}

func (r fixtureRepo) run(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(r.git, args...)
	cmd.Dir = r.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// build cross-compiles the fixture like scripts/build-dist.go, with extra
// arguments and environment entries.
func (r fixtureRepo) build(t *testing.T, goos, goarch string, args []string, env ...string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "fixture")
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), append(append([]string{"build", "-o", out}, args...), ".")...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(), "GOFLAGS=", "GOENV=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOWORK=off", "GOAMD64=", "GOARM64=", "GOEXPERIMENT=", "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	cmd.Env = append(cmd.Env, env...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %v %v: %v %s", args, env, err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var releaseFlags = []string{"-trimpath", "-ldflags", "-s -w -X fixture.Version=1.2.3"}

func TestCLIBinaryProvenance(t *testing.T) {
	r := newFixtureRepo(t)
	check := func(b []byte, goos, goarch, rev string) error {
		return checkCLIBinary(b, goos, goarch, rev, "fixture", "fixture")
	}
	for _, target := range [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"}} {
		b := r.build(t, target[0], target[1], releaseFlags)
		if err := check(b, target[0], target[1], r.rev); err != nil {
			t.Fatalf("%s/%s release build refused: %v", target[0], target[1], err)
		}
	}
	good := r.build(t, "linux", "amd64", releaseFlags)
	for _, tc := range []struct {
		name, goos, goarch, rev, want string
	}{
		{"wrong architecture", "linux", "arm64", r.rev, "ELF file is not"},
		{"wrong operating system", "windows", "amd64", r.rev, ""},
		{"wrong revision", "linux", "amd64", strings.Repeat("0", 40), "vcs.revision"},
		{"no revision", "linux", "amd64", "", "missing expected revision"},
	} {
		if err := check(good, tc.goos, tc.goarch, tc.rev); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
	if err := CheckCLIBinary(good, "linux", "amd64", r.rev); err == nil || !strings.Contains(err.Error(), "unexpected main package") {
		t.Fatalf("foreign main package accepted: %v", err)
	}
	for _, tc := range []struct {
		name string
		args []string
		env  []string
		want string
	}{
		{"without -trimpath", []string{"-ldflags", "-s -w"}, nil, "-trimpath"},
		{"extra build tags", append([]string{"-tags", "extra"}, releaseFlags...), nil, "unexpected build setting -tags"},
		{"build flags from GOFLAGS", releaseFlags, []string{"GOFLAGS=-gcflags=-N"}, "unexpected build setting -gcflags"},
		{"raised CPU level", releaseFlags, []string{"GOAMD64=v3"}, "GOAMD64"},
		{"without VCS stamping", append([]string{"-buildvcs=false"}, releaseFlags...), nil, "vcs"},
		{"with cgo", releaseFlags, []string{"CGO_ENABLED=1", "GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH}, ""},
	} {
		if tc.name == "with cgo" && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64") {
			continue
		}
		b := r.build(t, "linux", "amd64", tc.args, tc.env...)
		if err := check(b, "linux", "amd64", r.rev); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
	// A build from a tree with uncommitted changes carries the same revision.
	if err := os.WriteFile(filepath.Join(r.dir, "main.go"), []byte("package main\n\nfunc main() { println(\"changed\") }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	dirty := r.build(t, "linux", "amd64", releaseFlags)
	if err := check(dirty, "linux", "amd64", r.rev); err == nil || !strings.Contains(err.Error(), "vcs.modified") {
		t.Fatalf("modified tree accepted: %v", err)
	}
}

// gomobile is not available in unit tests; the settings mirror a gomobile
// bind of ./androidcore.
func TestAndroidLibraryProvenance(t *testing.T) {
	// deps mirrors gomobile's generated go.mod, which replaces bimeron and the
	// vendored snapshots with absolute directories.
	deps := func(root, sep string) []*debug.Module {
		return []*debug.Module{
			{Path: "bimeron", Version: "v0.0.0-00010101000000-000000000000", Replace: &debug.Module{Path: root, Version: "(devel)"}},
			{Path: "github.com/quic-go/quic-go", Version: "v0.64.1", Replace: &debug.Module{Path: root + sep + "third_party" + sep + "quic-go", Version: "(devel)"}},
			{Path: "golang.org/x/net", Version: "v0.62.0", Sum: "h1:x"},
		}
	}
	info := func(settings ...string) *debug.BuildInfo {
		bi := &debug.BuildInfo{Path: "gobind/gobind", Deps: deps(AndroidSourceLink, "/")}
		for _, s := range settings {
			k, v, _ := strings.Cut(s, "=")
			bi.Settings = append(bi.Settings, debug.BuildSetting{Key: k, Value: v})
		}
		return bi
	}
	trimmed := []string{"-buildmode=c-shared", "-compiler=gc", "-trimpath=true", "CGO_ENABLED=1", "GOARCH=arm64", "GOOS=android", "GOARM64=v8.0"}
	if err := checkAndroidInfo(info(trimmed...), "arm64"); err != nil {
		t.Fatal(err)
	}
	if err := checkAndroidInfo(info("-buildmode=c-shared", "-compiler=gc", "CGO_ENABLED=1", "GOARCH=arm", "GOOS=android", "GOARM=7", "-trimpath=true", "DefaultGODEBUG=x=1"), "arm"); err != nil {
		t.Fatal(err)
	}
	// scripts/build-android.ps1 builds from the root of a temporary drive.
	if err := checkAndroidInfo(&debug.BuildInfo{Path: "gobind/gobind", Deps: deps(`Z:\`, ""), Settings: info(trimmed...).Settings}, "arm64"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		bi     *debug.BuildInfo
		goarch string
		want   string
	}{
		{"untrimmed", info("-buildmode=c-shared", "-compiler=gc", "-ldflags=-X bimeron/core.Version=1", "CGO_ENABLED=1", "CGO_CFLAGS=-O2 -g", "GOARCH=arm64", "GOOS=android", "GOARM64=v8.0"), "arm64", "-trimpath"},
		{"wrong ABI", info(trimmed...), "amd64", "build setting GOARCH"},
		{"built from a home directory", &debug.BuildInfo{Path: "gobind/gobind", Deps: deps("/home/builder/bimeron-core", "/"), Settings: info(trimmed...).Settings}, "arm64", "module bimeron was built from"},
		{"vendored module outside the source", &debug.BuildInfo{Path: "gobind/gobind", Deps: append(deps(AndroidSourceLink, "/"), &debug.Module{Path: "example.com/m", Version: "v1.0.0", Replace: &debug.Module{Path: "/home/builder/m", Version: "(devel)"}}), Settings: info(trimmed...).Settings}, "arm64", "module example.com/m was built from"},
		{"lowercase drive", &debug.BuildInfo{Path: "gobind/gobind", Deps: deps(`z:\`, ""), Settings: info(trimmed...).Settings}, "arm64", "module bimeron was built from"},
		{"extra tags", info(append(trimmed, "-tags=extra")...), "arm64", "unexpected build setting -tags"},
		{"duplicate setting", info(append(trimmed, "GOOS=linux")...), "arm64", "duplicate"},
		{"foreign package", &debug.BuildInfo{Path: "gobind/gobind", Settings: info(trimmed...).Settings}, "arm64", "unexpected main package"},
	} {
		if err := checkAndroidInfo(tc.bi, tc.goarch); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
	if err := CheckAndroidLibrary([]byte("not an ELF file"), "arm64-v8a"); err == nil {
		t.Fatal("invalid library accepted")
	}
	if err := CheckAndroidLibrary(nil, "mips"); err == nil || !strings.Contains(err.Error(), "unknown Android ABI") {
		t.Fatalf("unknown ABI accepted: %v", err)
	}
}
