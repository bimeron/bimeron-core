package release_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestGenerationAndTamper(t *testing.T) {
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
	if !strings.Contains(string(data), `"channel": "beta"`) || !strings.Contains(string(data), `"size":`) {
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
