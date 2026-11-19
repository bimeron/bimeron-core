package release_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"bimeron/internal/releasecard"
	"bimeron/release"
)

func TestManifestGenerationAndTamper(t *testing.T) {
	isolateSignerEnv(t)
	dir := t.TempDir()
	for _, platform := range []string{"windows", "linux"} {
		for _, arch := range []string{"amd64", "arm64"} {
			name := "bimeron-v0.1.0-beta.2-" + platform + "-" + arch + ".zip"
			if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	seed := make([]byte, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)
	run := func(verify bool) error {
		args := []string{"run", "../scripts/release-manifest.go", "-tag", "v0.1.0-beta.2", "-dir", dir, "-compat", "compatibility.json"}
		if verify {
			args = append(args, "-verify")
		}
		cmd := exec.Command("go", args...)
		cmd.Env = append(os.Environ(), "BIMERON_RELEASE_ED25519_KEY="+base64.StdEncoding.EncodeToString(key))
		cmd.Env = append(cmd.Env, "BIMERON_RELEASE_ED25519_PUBLIC_KEY="+base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
		out, err := cmd.CombinedOutput()
		if err != nil {
			return &commandError{err, string(out)}
		}
		return nil
	}
	if err := run(false); err != nil {
		t.Fatal(err)
	}
	if err := run(true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "update-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"channel": "beta"`) || !strings.Contains(string(data), `"size":`) || !strings.Contains(string(data), `"gui_min": "0.3.0"`) || !strings.Contains(string(data), `"gui_max_exclusive": "0.3.2"`) || !strings.Contains(string(data), `"gui_reviewed": true`) {
		t.Fatal(string(data))
	}
	signature, err := os.ReadFile(filepath.Join(dir, "update-manifest.json.sig"))
	if err != nil {
		t.Fatal(err)
	}
	if err := run(false); err != nil {
		t.Fatal(err)
	}
	repeated, err := os.ReadFile(filepath.Join(dir, "update-manifest.json"))
	if err != nil || string(repeated) != string(data) {
		t.Fatal("manifest is not deterministic", err)
	}
	repeatedSignature, err := os.ReadFile(filepath.Join(dir, "update-manifest.json.sig"))
	if err != nil || string(repeatedSignature) != string(signature) {
		t.Fatal("signature is not deterministic", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "update-manifest.json"), append(data, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(true); err == nil {
		t.Fatal("manifest tampering accepted")
	}
	if err := run(false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bimeron-v0.1.0-beta.2-linux-arm64.zip"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(true); err == nil {
		t.Fatal("archive tampering accepted")
	}
}

func TestStableManifestRejectsWrongKeyAndMissingArchive(t *testing.T) {
	isolateSignerEnv(t)
	dir := t.TempDir()
	for _, platform := range []string{"windows", "linux"} {
		for _, arch := range []string{"amd64", "arm64"} {
			name := "bimeron-v0.2.0-" + platform + "-" + arch + ".zip"
			if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	args := []string{"run", "../scripts/release-manifest.go", "-tag", "v0.2.0", "-dir", dir, "-compat", "compatibility.json"}
	invoke := func(verify bool, public string) error {
		commandArgs := append([]string(nil), args...)
		if verify {
			commandArgs = append(commandArgs, "-verify")
		}
		cmd := exec.Command("go", commandArgs...)
		cmd.Env = append(os.Environ(), "BIMERON_RELEASE_ED25519_KEY="+base64.StdEncoding.EncodeToString(key), "BIMERON_RELEASE_ED25519_PUBLIC_KEY="+public)
		_, err := cmd.CombinedOutput()
		return err
	}
	pub := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	if err := invoke(false, pub); err != nil {
		t.Fatal(err)
	}
	reviewed := exec.Command("go", append(append([]string(nil), args...), "-require-reviewed")...)
	reviewed.Env = append(os.Environ(), "BIMERON_RELEASE_ED25519_KEY="+base64.StdEncoding.EncodeToString(key), "BIMERON_RELEASE_ED25519_PUBLIC_KEY="+pub)
	if output, err := reviewed.CombinedOutput(); err != nil {
		t.Fatalf("reviewed GUI compatibility rejected: %s: %v", output, err)
	}
	provisional, err := os.ReadFile("compatibility.json")
	if err != nil {
		t.Fatal(err)
	}
	provisional = []byte(strings.Replace(string(provisional), `"gui_reviewed": true`, `"gui_reviewed": false`, 1))
	provisionalPath := filepath.Join(dir, "provisional-compatibility.json")
	if err := os.WriteFile(provisionalPath, provisional, 0600); err != nil {
		t.Fatal(err)
	}
	unreviewedArgs := append(append([]string(nil), args...), "-compat", provisionalPath, "-require-reviewed")
	unreviewed := exec.Command("go", unreviewedArgs...)
	unreviewed.Env = reviewed.Env
	if err := unreviewed.Run(); err == nil {
		t.Fatal("unreviewed GUI compatibility accepted for publication")
	}
	if err := invoke(false, pub); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "update-manifest.json"))
	if err != nil || !strings.Contains(string(data), `"channel": "stable"`) {
		t.Fatal(err, string(data))
	}
	if err := invoke(true, base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))); err == nil {
		t.Fatal("wrong public key accepted")
	}
	if err := invoke(true, pub); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "bimeron-v0.2.0-linux-arm64.zip")); err != nil {
		t.Fatal(err)
	}
	if err := invoke(false, pub); err == nil {
		t.Fatal("missing archive accepted")
	}
}

type commandError struct {
	cause  error
	output string
}

func (e *commandError) Error() string { return e.cause.Error() + ": " + e.output }

// The hardware signer accepts at most releasecard.MaxManifestSize bytes; the
// publisher must refuse a larger manifest for every key type, and the current
// manifest shape must stay well below the bound.
func TestManifestSizeBound(t *testing.T) {
	isolateSignerEnv(t)
	dir := t.TempDir()
	for _, platform := range []string{"windows", "linux"} {
		for _, arch := range []string{"amd64", "arm64"} {
			name := "bimeron-v0.12.34-beta.56-" + platform + "-" + arch + ".zip"
			if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	sign := func(compat string) (string, error) {
		cmd := exec.Command("go", "run", "../scripts/release-manifest.go", "-tag", "v0.12.34-beta.56", "-dir", dir, "-compat", compat)
		cmd.Env = append(os.Environ(), "BIMERON_RELEASE_ED25519_KEY="+base64.StdEncoding.EncodeToString(key))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := sign("compatibility.json"); err != nil {
		t.Fatal(err, out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "update-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > releasecard.MaxManifestSize*3/4 {
		t.Fatalf("manifest is %d bytes, close to the %d-byte hardware signing bound", len(data), releasecard.MaxManifestSize)
	}
	compat, err := os.ReadFile("compatibility.json")
	if err != nil {
		t.Fatal(err)
	}
	large := strings.Replace(string(compat), `"gui_min": "0.3.0"`, `"gui_min": "0.3.0-`+strings.Repeat("x", releasecard.MaxManifestSize)+`"`, 1)
	largePath := filepath.Join(dir, "large-compatibility.json")
	if err := os.WriteFile(largePath, []byte(large), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := sign(largePath); err == nil || !strings.Contains(out, "at most 2560 bytes") {
		t.Fatalf("oversized manifest was not refused: %v %s", err, out)
	}
}

// isolateSignerEnv clears signer settings inherited from the developer's
// environment and allows the fixed test key, which no verifier pins.
func isolateSignerEnv(t *testing.T) {
	t.Helper()
	t.Setenv("BIMERON_RELEASE_CARD_SERIAL", "")
	t.Setenv("BIMERON_RELEASE_ED25519_KEY", "")
	t.Setenv("BIMERON_RELEASE_ED25519_PUBLIC_KEY", "")
	t.Setenv("BIMERON_RELEASE_TEST_UNPINNED_KEY", "1")
}

// Every key is limited to its release range, so a release that Core repair
// (hardware keys only) would reject cannot be published. These checks run
// before any card, signature or archive is touched.
func TestManifestKeyPolicy(t *testing.T) {
	isolateSignerEnv(t)
	dir := t.TempDir()
	compat, err := os.ReadFile("compatibility.json")
	if err != nil {
		t.Fatal(err)
	}
	hardwareCompat := filepath.Join(dir, "hardware-compatibility.json")
	data := strings.Replace(string(compat), `"gui_min": "0.3.0"`, `"gui_min": "0.3.1"`, 1)
	if err := os.WriteFile(hardwareCompat, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(tag, compatPath string, env ...string) string {
		t.Helper()
		args := []string{"run", "../scripts/release-manifest.go", "-tag", tag, "-dir", dir, "-compat", compatPath}
		// Card signing is checked without -verify; the policy refuses before any card is opened.
		if !strings.Contains(strings.Join(env, " "), "BIMERON_RELEASE_CARD_SERIAL=2") {
			args = append(args, "-verify")
		}
		cmd := exec.Command("go", args...)
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("%s accepted with %v", tag, env)
		}
		return string(out)
	}
	legacy := "BIMERON_RELEASE_ED25519_PUBLIC_KEY=" + release.LegacyReleaseKey
	hardware := "BIMERON_RELEASE_ED25519_PUBLIC_KEY=" + release.HardwareReleaseKeys[0]
	card := "BIMERON_RELEASE_CARD_SERIAL=22337246"
	for _, tc := range []struct {
		name, tag, compat, want string
		env                     []string
	}{
		{"legacy key after beta.2", "v0.4.0-beta.3", hardwareCompat, "is retired", []string{legacy}},
		{"legacy key on a card", "v0.4.0", hardwareCompat, "is retired", []string{legacy, card}},
		{"hardware key on a legacy tag", "v0.4.0-beta.2", "compatibility.json", "only releases after v0.4.0-beta.2", []string{hardware}},
		{"hardware gui_min below 0.3.1", "v0.4.0-beta.3", "compatibility.json", "gui_min must be at least 0.3.1", []string{hardware}},
		{"unpinned key outside tests", "v0.4.0-beta.3", hardwareCompat, "not a release signing key", []string{"BIMERON_RELEASE_ED25519_PUBLIC_KEY=" + base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)), "BIMERON_RELEASE_TEST_UNPINNED_KEY="}},
	} {
		if out := run(tc.tag, tc.compat, tc.env...); !strings.Contains(out, tc.want) {
			t.Fatalf("%s: got %q, want %q", tc.name, out, tc.want)
		}
	}
	// With an allowed key and gui_min the policy passes and verification
	// proceeds to the (absent) archives.
	if out := run("v0.4.0-beta.3", hardwareCompat, hardware); strings.Contains(out, "gui_min") || strings.Contains(out, "signing key") || strings.Contains(out, "retired") || strings.Contains(out, "only releases after") {
		t.Fatalf("allowed hardware key refused by policy: %s", out)
	}
	if out := run("v0.4.0-beta.2", "compatibility.json", legacy); strings.Contains(out, "retired") || strings.Contains(out, "signing key") {
		t.Fatalf("legacy key refused for a legacy tag: %s", out)
	}
}
