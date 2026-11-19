package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// HardwareReleaseKeys are the YubiKey release signing keys (docs/RELEASE_KEYS.md)
// for every release after LastLegacyTag. Core repair acquisition trusts exactly
// these keys, so the publisher refuses any other key for those tags.
var HardwareReleaseKeys = []string{
	"lRcnhdj4yU4TrinOa4U177FG7wrwUPv/v9zxA/WiJMI=", // e6fb20d55656904a, YubiKey A (primary)
	"6K8uY/1qIogN2j3ZdpEr4PuTqXzH7EseTd6kzHxpIr4=", // 095d295f5fe9a4e2, YubiKey B (backup)
}

// LegacyReleaseKey is the retiring software key 7370a2d8cf890e5e. It only
// verifies LegacyReleaseTags; the publisher never signs with it again.
const LegacyReleaseKey = "bk6SfABmDG88uhUupYT+ia6dtSrpHbnGaBCfYvihJF0="

// LastLegacyTag is the last release signed by LegacyReleaseKey. Every new tag
// must sort after it and is signed with a hardware key.
const LastLegacyTag = "v0.4.0-beta.2"

// LegacyReleaseTags are the published releases (and the frozen v0.4.0-beta.2
// candidate) whose manifests LegacyReleaseKey may verify. The key is never
// accepted for any other tag, so no new release can depend on it.
var LegacyReleaseTags = []string{
	"v0.1.0-beta.1", "v0.1.0-beta.2", "v0.1.0-beta.3", "v0.1.0-beta.4", "v0.1.0-beta.5",
	"v0.2.0-beta.1", "v0.3.0-beta.2", "v0.4.0-beta.1", LastLegacyTag,
}

// HardwareGUIMin is the oldest Desktop version that pins the hardware keys.
// Older Desktop versions cannot verify hardware-signed releases, so their
// manifests must not claim to support them.
const HardwareGUIMin = "0.3.1"

// KeyID is the manifest key identifier: the first eight bytes of the SHA-256 of
// the public key, as 16 lowercase hex digits.
func KeyID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func decodeKey(s string) []byte {
	k, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(k) != ed25519.PublicKeySize {
		panic("invalid embedded release key " + s)
	}
	return k
}

// DecodedHardwareReleaseKeys returns HardwareReleaseKeys as raw public keys.
func DecodedHardwareReleaseKeys() [][]byte {
	keys := make([][]byte, 0, len(HardwareReleaseKeys))
	for _, s := range HardwareReleaseKeys {
		keys = append(keys, decodeKey(s))
	}
	return keys
}

// IsHardwareReleaseKey reports whether pub is one of HardwareReleaseKeys.
func IsHardwareReleaseKey(pub []byte) bool {
	for _, k := range DecodedHardwareReleaseKeys() {
		if bytes.Equal(k, pub) {
			return true
		}
	}
	return false
}

// KeyUse classifies pub for a release tag.
type KeyUse int

const (
	// KeyRefused may not sign or verify the tag.
	KeyRefused KeyUse = iota
	// KeyLegacy is LegacyReleaseKey on a tag up to LastLegacyTag.
	KeyLegacy
	// KeyHardware is a hardware key on a tag after LastLegacyTag.
	KeyHardware
	// KeyUnpinned is trusted by no verifier; only tests may use it.
	KeyUnpinned
)

// SigningKeyUse decides whether pub may sign or verify the manifest for tag.
// The legacy key covers only LegacyReleaseTags; every other tag must sort after
// LastLegacyTag and uses a hardware key. A key no verifier pins is reported as
// KeyUnpinned for the caller to refuse outside tests.
func SigningKeyUse(tag string, pub []byte) (KeyUse, error) {
	after, err := tagAfter(tag, LastLegacyTag)
	if err != nil {
		return KeyRefused, err
	}
	listed := false
	for _, t := range LegacyReleaseTags {
		listed = listed || t == tag
	}
	if !listed && !after {
		return KeyRefused, fmt.Errorf("tag %s is not a published legacy release and does not sort after %s; new releases need a later tag and a hardware key (docs/RELEASE_KEYS.md)", tag, LastLegacyTag)
	}
	legacy := bytes.Equal(pub, decodeKey(LegacyReleaseKey))
	hardware := IsHardwareReleaseKey(pub)
	switch {
	case legacy && listed:
		return KeyLegacy, nil
	case hardware && after:
		return KeyHardware, nil
	case legacy:
		return KeyRefused, fmt.Errorf("key %s is retired: it may only verify published releases up to %s, not %s; use a hardware key (docs/RELEASE_KEYS.md)", KeyID(pub), LastLegacyTag, tag)
	case hardware:
		return KeyRefused, fmt.Errorf("hardware key %s may sign only releases after %s, not %s", KeyID(pub), LastLegacyTag, tag)
	}
	return KeyUnpinned, nil
}

// SemVer 2.0 without build metadata: no leading zeros in numeric identifiers
// and no empty prerelease identifiers.
var semverPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$`)

// CompareVersions orders SemVer 2.0 versions with an optional "v" prefix.
func CompareVersions(a, b string) (int, error) {
	ma, mb := semverPattern.FindStringSubmatch(a), semverPattern.FindStringSubmatch(b)
	if ma == nil {
		return 0, fmt.Errorf("invalid version %q", a)
	}
	if mb == nil {
		return 0, fmt.Errorf("invalid version %q", b)
	}
	for i := 1; i <= 3; i++ {
		if c := compareNumeric(ma[i], mb[i]); c != 0 {
			return c, nil
		}
	}
	switch {
	case ma[4] == mb[4]:
		return 0, nil
	case ma[4] == "":
		return 1, nil
	case mb[4] == "":
		return -1, nil
	}
	pa, pb := strings.Split(ma[4], "."), strings.Split(mb[4], ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.ParseUint(pa[i], 10, 64)
		nb, eb := strconv.ParseUint(pb[i], 10, 64)
		var c int
		switch {
		case ea == nil && eb == nil:
			c = compareUint(na, nb)
		case ea == nil:
			c = -1
		case eb == nil:
			c = 1
		default:
			c = strings.Compare(pa[i], pb[i])
		}
		if c != 0 {
			return c, nil
		}
	}
	return compareUint(uint64(len(pa)), uint64(len(pb))), nil
}

func compareNumeric(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return compareUint(uint64(len(a)), uint64(len(b)))
	}
	return strings.Compare(a, b)
}

func compareUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func tagAfter(tag, ref string) (bool, error) {
	c, err := CompareVersions(tag, ref)
	return c > 0, err
}
