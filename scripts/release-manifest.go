//go:build ignore

// Usage: ./scripts/release-go.ps1 run scripts/release-manifest.go -tag vX.Y.Z -dir release [-verify]
//
// Signing uses BIMERON_RELEASE_CARD_SERIAL (an OpenPGP hardware token such as
// a YubiKey, with BIMERON_RELEASE_ED25519_PUBLIC_KEY naming its pinned key).
// Signing and -verify accept only the keys allowed for the tag
// (release.SigningKeyUse); the retired software key only verifies. Tests set
// BIMERON_RELEASE_TEST_UNPINNED_KEY=1 to sign with an unpinned software key in
// BIMERON_RELEASE_ED25519_KEY. Card PIN entry needs a real console (PowerShell
// or cmd), not mintty.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/buildinfo"
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
	"strconv"
	"strings"

	"bimeron/internal/releasecard"
	"bimeron/release"

	"golang.org/x/term"
)

const manifestName = "update-manifest.json"

var tagPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)

type compatibility struct {
	Schema          int     `json:"schema"`
	IPCMin          int     `json:"ipc_min"`
	IPCMax          int     `json:"ipc_max"`
	GUIMin          *string `json:"gui_min"`
	GUIMaxExclusive *string `json:"gui_max_exclusive"`
	GUIReviewed     bool    `json:"gui_reviewed"`
	ProfileFormat   int     `json:"profile_format"`
}
type archive struct {
	OS                 string `json:"os"`
	Arch               string `json:"arch"`
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	SHA256             string `json:"sha256"`
	UpdateHoldContract int    `json:"kill_switch_update_hold_contract,omitempty"`
	ExecutableSHA256   string `json:"executable_sha256,omitempty"`
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

func run(tag, dir, compatPath string, verify, requireReviewed bool) error {
	if !tagPattern.MatchString(tag) {
		return fmt.Errorf("invalid release tag %q", tag)
	}
	var private ed25519.PrivateKey
	var pub ed25519.PublicKey
	var err error
	cardSerial := os.Getenv("BIMERON_RELEASE_CARD_SERIAL")
	if verify || cardSerial != "" {
		// A hardware key is identified by the pinned public key; the card must hold it.
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
	// Repair acquisition and Desktop pin specific keys per release range; refuse
	// a key that would publish a release some verifier cannot accept.
	use, err := release.SigningKeyUse(tag, pub)
	if err != nil {
		return err
	}
	if use == release.KeyUnpinned && os.Getenv("BIMERON_RELEASE_TEST_UNPINNED_KEY") != "1" {
		return fmt.Errorf("key %s is not a release signing key (docs/RELEASE_KEYS.md)", release.KeyID(pub))
	}
	// Published legacy manifests stay verifiable, but nothing new is signed with
	// the retired key: a signature must only cover locally prepared bytes.
	if use == release.KeyLegacy && !verify {
		return fmt.Errorf("key %s is retired and only verifies published releases; it signs nothing new (docs/RELEASE_KEYS.md)", release.KeyID(pub))
	}
	var c compatibility
	data, err := os.ReadFile(compatPath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	if c.Schema != 1 || c.IPCMin < 1 || c.IPCMax < c.IPCMin || (c.GUIMin == nil) != (c.GUIMaxExclusive == nil) || c.ProfileFormat < 1 {
		return errors.New("invalid compatibility rules")
	}
	if c.GUIMin != nil && (*c.GUIMin == "" || *c.GUIMaxExclusive == "") {
		return errors.New("empty GUI compatibility bound")
	}
	if requireReviewed && (!c.GUIReviewed || c.GUIMin == nil) {
		return errors.New("GUI update compatibility is unavailable; review release/compatibility.json before publication")
	}
	if use == release.KeyHardware && c.GUIMin != nil {
		if cmp, err := release.CompareVersions(*c.GUIMin, release.HardwareGUIMin); err != nil || cmp < 0 {
			return fmt.Errorf("gui_min must be at least %s for a hardware-signed release: older Desktop versions do not pin the hardware keys", release.HardwareGUIMin)
		}
	}
	channel := "stable"
	if strings.Contains(tag, "-") {
		channel = "beta"
	}
	m := manifest{Schema: 1, Tag: tag, CoreVersion: strings.TrimPrefix(tag, "v"), Channel: channel, KeyID: release.KeyID(pub), Compatibility: c}
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
			if err != nil {
				f.Close()
				return err
			}
			artifact := archive{OS: platform, Arch: arch, Name: name, Size: info.Size(), SHA256: hex.EncodeToString(h.Sum(nil))}
			if platform == "windows" {
				artifact.UpdateHoldContract, artifact.ExecutableSHA256, err = windowsUpdateMetadata(f, info.Size(), name, arch)
				if err != nil {
					f.Close()
					return err
				}
			}
			f.Close()
			m.Archives = append(m.Archives, artifact)
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
	// Enforced for every signer so a manifest that outgrows hardware signing
	// fails in tests rather than during a release.
	if err := releasecard.CheckSize(len(canonical)); err != nil {
		return err
	}
	var raw []byte
	if cardSerial != "" {
		raw, err = cardSign(cardSerial, pub, canonical)
		if err != nil {
			return err
		}
	} else {
		raw = ed25519.Sign(private, canonical)
	}
	signature := []byte(base64.StdEncoding.EncodeToString(raw) + "\n")
	if err := os.WriteFile(manifestPath, canonical, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(sigPath, signature, 0644); err != nil {
		return err
	}
	return nil
}

func cardSign(serial string, pub ed25519.PublicKey, msg []byte) ([]byte, error) {
	n, err := strconv.ParseUint(serial, 10, 32)
	if err != nil || n == 0 {
		return nil, errors.New("BIMERON_RELEASE_CARD_SERIAL must be the decimal card serial number")
	}
	fd := int(os.Stdin.Fd())
	pin := func() ([]byte, error) {
		if !term.IsTerminal(fd) {
			return nil, errors.New("hardware signing needs an interactive console for the PIN")
		}
		fmt.Fprintf(os.Stderr, "Signing PIN for card %d: ", n)
		p, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err == nil && len(p) == 0 {
			err = errors.New("empty PIN")
		}
		return p, err
	}
	touch := func() { fmt.Fprintf(os.Stderr, "Touch the YubiKey (card %d) to sign the manifest...\n", n) }
	return releasecard.SignManifest(uint32(n), pub, msg, pin, touch)
}

func windowsUpdateMetadata(archive io.ReaderAt, size int64, path, arch string) (int, string, error) {
	z, err := zip.NewReader(archive, size)
	if err != nil {
		return 0, "", err
	}
	var executable *zip.File
	for _, f := range z.File {
		if f.Name == "windows-"+arch+"/bimeron.exe" {
			if executable != nil {
				return 0, "", fmt.Errorf("duplicate Windows executable in %s", path)
			}
			executable = f
		}
	}
	if executable == nil {
		return 0, "", nil
	}
	f, err := executable.Open()
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	const maxExecutableSize = 256 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxExecutableSize+1))
	if err != nil {
		return 0, "", err
	}
	if len(data) > maxExecutableSize {
		return 0, "", fmt.Errorf("Windows executable too large in %s", path)
	}
	info, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return 0, "", nil
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if info.Path != "bimeron/cmd/bimeron" || settings["GOOS"] != "windows" || settings["GOARCH"] != arch {
		return 0, "", nil
	}
	if !strings.Contains(" "+settings["-ldflags"]+" ", " -X main.windowsUpdateArtifactContract=1 ") {
		return 0, "", nil
	}
	digest := sha256.Sum256(data)
	return 1, hex.EncodeToString(digest[:]), nil
}
