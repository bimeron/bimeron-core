//go:build ignore

// Usage: go run scripts/release-manifest.go -tag vX.Y.Z -dir release [-verify]
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const manifestName = "update-manifest.json"

var tagPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)

type compatibility struct {
	Schema          int    `json:"schema"`
	IPCMin          int    `json:"ipc_min"`
	IPCMax          int    `json:"ipc_max"`
	GUIMin          string `json:"gui_min"`
	GUIMaxExclusive string `json:"gui_max_exclusive"`
	GUIReviewed     bool   `json:"gui_reviewed"`
	ProfileFormat   int    `json:"profile_format"`
}
type archive struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type manifest struct {
	Schema        int           `json:"schema"`
	Tag           string        `json:"tag"`
	CoreVersion   string        `json:"core_version"`
	Channel       string        `json:"channel"`
	KeyID         string        `json:"key_id"`
	Compatibility compatibility `json:"compatibility"`
	Archives      []archive     `json:"archives"`
}

func main() {
	tag := flag.String("tag", "", "release tag")
	dir := flag.String("dir", "release", "directory containing completed ZIPs")
	compat := flag.String("compat", "release/compatibility.json", "reviewed compatibility rules")
	verify := flag.Bool("verify", false, "verify existing manifest and signature")
	requireReviewed := flag.Bool("require-reviewed", false, "require confirmed GUI compatibility before publication")
	flag.Parse()
	if err := run(*tag, *dir, *compat, *verify, *requireReviewed); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func privateKey() (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(os.Getenv("BIMERON_RELEASE_ED25519_KEY"))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("BIMERON_RELEASE_ED25519_KEY must be a base64-encoded 64-byte Ed25519 private key")
	}
	if string(ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])) != string(raw) {
		return nil, errors.New("BIMERON_RELEASE_ED25519_KEY has an invalid public-key half")
	}
	return ed25519.PrivateKey(raw), nil
}
func publicKey() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(os.Getenv("BIMERON_RELEASE_ED25519_PUBLIC_KEY"))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("BIMERON_RELEASE_ED25519_PUBLIC_KEY must be a base64-encoded 32-byte Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}
func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func run(tag, dir, compatPath string, verify, requireReviewed bool) error {
	if !tagPattern.MatchString(tag) {
		return fmt.Errorf("invalid release tag %q", tag)
	}
	var private ed25519.PrivateKey
	var pub ed25519.PublicKey
	var err error
	if verify {
		pub, err = publicKey()
	} else {
		private, err = privateKey()
		if err == nil {
			pub = private.Public().(ed25519.PublicKey)
		}
		if configured := os.Getenv("BIMERON_RELEASE_ED25519_PUBLIC_KEY"); err == nil && configured != "" {
			trusted, keyErr := publicKey()
			if keyErr != nil {
				return keyErr
			}
			if !bytes.Equal(trusted, pub) {
				return errors.New("signing key does not match configured public key")
			}
		}
	}
	if err != nil {
		return err
	}
	var c compatibility
	data, err := os.ReadFile(compatPath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	if c.Schema != 1 || c.IPCMin < 1 || c.IPCMax < c.IPCMin || c.GUIMin == "" || c.GUIMaxExclusive == "" || c.ProfileFormat < 1 {
		return errors.New("invalid compatibility rules")
	}
	if requireReviewed && !c.GUIReviewed {
		return errors.New("GUI compatibility is provisional; review release/compatibility.json before publication")
	}
	channel := "stable"
	if strings.Contains(tag, "-") {
		channel = "beta"
	}
	m := manifest{Schema: 1, Tag: tag, CoreVersion: strings.TrimPrefix(tag, "v"), Channel: channel, KeyID: keyID(pub), Compatibility: c}
	for _, platform := range []string{"windows", "linux"} {
		for _, arch := range []string{"amd64", "arm64"} {
			name := fmt.Sprintf("bimeron-%s-%s-%s.zip", tag, platform, arch)
			f, err := os.Open(filepath.Join(dir, name))
			if err != nil {
				return err
			}
			info, err := f.Stat()
			if err != nil || !info.Mode().IsRegular() {
				f.Close()
				return fmt.Errorf("invalid archive %s", name)
			}
			h := sha256.New()
			_, err = io.Copy(h, f)
			f.Close()
			if err != nil {
				return err
			}
			m.Archives = append(m.Archives, archive{platform, arch, name, info.Size(), hex.EncodeToString(h.Sum(nil))})
		}
	}
	canonical, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	canonical = append(canonical, '\n')
	manifestPath := filepath.Join(dir, manifestName)
	sigPath := manifestPath + ".sig"
	if verify {
		onDisk, err := os.ReadFile(manifestPath)
		if err != nil {
			return err
		}
		onDiskSig, err := os.ReadFile(sigPath)
		if err != nil {
			return err
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(string(onDiskSig), "\n"))
		if err != nil || len(decoded) != ed25519.SignatureSize || string(onDiskSig) != base64.StdEncoding.EncodeToString(decoded)+"\n" || !ed25519.Verify(pub, onDisk, decoded) {
			return errors.New("invalid manifest signature")
		}
		if string(onDisk) != string(canonical) {
			return errors.New("manifest differs from completed archives or compatibility rules")
		}
		return nil
	}
	signature := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical)) + "\n")
	if err := os.WriteFile(manifestPath, canonical, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(sigPath, signature, 0644); err != nil {
		return err
	}
	return nil
}
