package main

import (
	"archive/zip"
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
	m.Compatibility.Schema = 1
	m.Compatibility.Reviewed = true
	m.Compatibility.Min = "0.2.0"
	m.Compatibility.Max = "0.2.1"
	m.Compatibility.IPCMin = 1
	m.Compatibility.IPCMax = 1
	m.Compatibility.Profile = 1
	for _, platform := range []string{"windows", "linux"} {
		for _, arch := range []string{"amd64", "arm64"} {
			m.Archives = append(m.Archives, repairArchive{platform, arch, "bimeron-v0.2.0-beta.1-" + platform + "-" + arch + ".zip", int64(b.Len()), hex.EncodeToString(h[:])})
		}
	}
	verify := func() (repairArchive, error) {
		data, _ := json.Marshal(m)
		data = append(data, '\n')
		sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)) + "\n")
		return verifyRepairManifest(data, sig, pub, m.Version, "windows", "amd64")
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
	if _, err = verifyRepairManifest(data, sig, pub, m.Version, "windows", "amd64"); err == nil {
		t.Fatal("accepted bad signature")
	}
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
