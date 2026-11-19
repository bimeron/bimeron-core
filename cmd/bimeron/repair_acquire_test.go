package main

import (
	"archive/zip"
	"bimeron/release"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepairAcquisitionSignatureAndArchive(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, _ := z.Create("windows-amd64/wintun.dll")
	w.Write([]byte("fixture"))
	z.Close()
	h := sha256.Sum256(b.Bytes())
	kh := sha256.Sum256(pub)
	m := repairManifest{Schema: 1, KeyID: hex.EncodeToString(kh[:8]), Tag: "v0.2.0-beta.1", Version: "0.2.0-beta.1", Channel: "beta"}
	m.Compatibility = repairCompatibilityFromSource(t)
	for _, platform := range []string{"windows", "linux"} {
		for _, arch := range []string{"amd64", "arm64"} {
			m.Archives = append(m.Archives, repairArchive{platform, arch, "bimeron-v0.2.0-beta.1-" + platform + "-" + arch + ".zip", int64(b.Len()), hex.EncodeToString(h[:])})
		}
	}
	verify := func() (repairArchive, error) {
		data, _ := json.Marshal(m)
		data = append(data, '\n')
		sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)) + "\n")
		return verifyRepairManifest(data, sig, [][]byte{pub}, m.Version, "windows", "amd64")
	}
	a, err := verify()
	if err != nil {
		t.Fatal(err)
	}
	out, err := extractRepairMember(b.Bytes(), a, "wintun.dll")
	if err != nil || string(out) != "fixture" {
		t.Fatal(err)
	}
	if _, err = extractRepairMember(append(b.Bytes(), 0), a, "wintun.dll"); err == nil {
		t.Fatal("accepted modified archive")
	}
	m.Compatibility.Reviewed = false
	if _, err = verify(); err == nil {
		t.Fatal("accepted unreviewed")
	}
	m.Compatibility.Reviewed = true
	m.Archives[1] = m.Archives[0]
	if _, err = verify(); err == nil {
		t.Fatal("accepted duplicate target")
	}
	data := []byte("{}\n")
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)) + "\n")
	data[0] = '['
	if _, err = verifyRepairManifest(data, sig, [][]byte{pub}, m.Version, "windows", "amd64"); err == nil {
		t.Fatal("accepted bad signature")
	}
}

// Read the publisher's source file independently of the embedded accessor so
// the signed acceptance fixtures detect drift between publication and repair.
func repairCompatibilityFromSource(t *testing.T) release.Compatibility {
	t.Helper()
	data, err := os.ReadFile("../../release/compatibility.json")
	if err != nil {
		t.Fatal(err)
	}
	var c release.Compatibility
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	return c
}
func TestRepairDownloadPolicy(t *testing.T) {
	for _, s := range []string{"http://github.com/a", "https://evil.example/a", "https://github.com:443/a", "https://user@github.com/a", "https://github.com.evil/a"} {
		u, _ := url.Parse(s)
		if repairDownloadURL(u) {
			t.Fatal(s)
		}
	}
	u, _ := url.Parse("https://release-assets.githubusercontent.com/a")
	if !repairDownloadURL(u) {
		t.Fatal("asset host")
	}
}
func TestRepairDownloadExclusive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "source")
	if err := writeRepairDownload(p, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeRepairDownload(p, []byte("second")); err == nil {
		t.Fatal("overwrote existing")
	}
	data, _ := os.ReadFile(p)
	if string(data) != "first" {
		t.Fatal("changed source")
	}
}
func TestRepairManifestRejectsDuplicateKeys(t *testing.T) {
	for _, data := range []string{`{"schema":1,"schema":1}`, `{"a":{"x":1,"x":2}}`, `{} {}`} {
		if repairJSONUnique([]byte(data)) {
			t.Fatal(data)
		}
	}
	if !repairJSONUnique([]byte(`{"a":[{"x":1},{"x":2}]}`)) {
		t.Fatal("valid nested JSON")
	}
}
func TestRepairTrustsOnlyHardwareReleaseKeys(t *testing.T) {
	want := []string{"e6fb20d55656904a", "095d295f5fe9a4e2"}
	keys := decodeRepairKeys()
	if len(keys) != len(want) {
		t.Fatalf("trusted %d repair keys, want %d", len(keys), len(want))
	}
	for i, k := range keys {
		sum := sha256.Sum256(k)
		if len(k) != ed25519.PublicKeySize || hex.EncodeToString(sum[:8]) != want[i] {
			t.Fatalf("repair key %d does not match docs/RELEASE_KEYS.md", i)
		}
	}
	// The publisher refuses any other key for releases this source can build,
	// so a release that repair would reject cannot be published.
	if strings.Join(repairUpdateKeys, ",") != strings.Join(release.HardwareReleaseKeys, ",") {
		t.Fatal("repair trust differs from the publisher's hardware key allowlist")
	}
}

func TestRepairManifestSelectsSigningKey(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	trusted := [][]byte{pubA, pubB}
	id := func(k ed25519.PublicKey) string { s := sha256.Sum256(k); return hex.EncodeToString(s[:8]) }
	m := repairManifest{Schema: 1, Tag: "v0.2.0", Version: "0.2.0", Channel: "stable", Compatibility: repairCompatibilityFromSource(t)}
	for _, p := range []string{"windows", "linux"} {
		for _, a := range []string{"amd64", "arm64"} {
			m.Archives = append(m.Archives, repairArchive{p, a, "bimeron-v0.2.0-" + p + "-" + a + ".zip", 1, hex.EncodeToString(make([]byte, 32))})
		}
	}
	verify := func(keyID string, priv ed25519.PrivateKey, keys [][]byte) error {
		m.KeyID = keyID
		data, _ := json.Marshal(m)
		data = append(data, '\n')
		sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)) + "\n")
		_, err := verifyRepairManifest(data, sig, keys, "0.2.0", "windows", "amd64")
		return err
	}
	if err := verify(id(pubB), privB, trusted); err != nil {
		t.Fatal("backup key rejected:", err)
	}
	if err := verify(id(pubA), privA, trusted); err != nil {
		t.Fatal("primary key rejected:", err)
	}
	if verify(id(pubA), privB, trusted) == nil {
		t.Fatal("accepted a key_id naming a different trusted key")
	}
	_, untrusted, _ := ed25519.GenerateKey(rand.Reader)
	if verify(id(untrusted.Public().(ed25519.PublicKey)), untrusted, trusted) == nil {
		t.Fatal("accepted an untrusted key")
	}
	if verify(id(pubA), privA, nil) == nil {
		t.Fatal("accepted with no trusted keys")
	}
}
