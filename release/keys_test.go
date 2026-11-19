package release

import (
	"crypto/ed25519"
	"testing"
)

func TestReleaseKeyIDs(t *testing.T) {
	want := []string{"e6fb20d55656904a", "095d295f5fe9a4e2"}
	keys := DecodedHardwareReleaseKeys()
	if len(keys) != len(want) {
		t.Fatalf("%d hardware keys, want %d", len(keys), len(want))
	}
	for i, k := range keys {
		if KeyID(k) != want[i] {
			t.Fatalf("hardware key %d has ID %s, want %s", i, KeyID(k), want[i])
		}
	}
	if KeyID(decodeKey(LegacyReleaseKey)) != "7370a2d8cf890e5e" {
		t.Fatal("legacy key ID")
	}
}

func TestCompareVersions(t *testing.T) {
	ordered := []string{"v0.1.0-beta.5", "v0.4.0-beta.2", "v0.4.0-beta.3", "v0.4.0-beta.10", "v0.4.0-rc.1", "v0.4.0", "v0.4.1", "v0.10.0", "v1.0.0"}
	for i := range ordered {
		for j := range ordered {
			c, err := CompareVersions(ordered[i], ordered[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if err != nil || c != want {
				t.Fatalf("compare %s %s = %d, %v; want %d", ordered[i], ordered[j], c, err, want)
			}
		}
	}
	for _, p := range [][2]string{{"0.3.1", "0.3.1"}, {"v0.3.1", "0.3.1"}, {"1.0.0-1", "1.0.0-1"}} {
		if c, err := CompareVersions(p[0], p[1]); err != nil || c != 0 {
			t.Fatalf("%s != %s", p[0], p[1])
		}
	}
	if c, _ := CompareVersions("1.0.0-1", "1.0.0-alpha"); c != -1 {
		t.Fatal("numeric prerelease identifiers sort before alphanumeric ones")
	}
	if c, _ := CompareVersions("1.0.0-alpha", "1.0.0-alpha.1"); c != -1 {
		t.Fatal("a shorter prerelease sorts first")
	}
	if _, err := CompareVersions("v0.4", "v0.4.0"); err == nil {
		t.Fatal("accepted an incomplete version")
	}
}

func TestSigningKeyUse(t *testing.T) {
	legacy := decodeKey(LegacyReleaseKey)
	a, b := DecodedHardwareReleaseKeys()[0], DecodedHardwareReleaseKeys()[1]
	other, _, _ := ed25519.GenerateKey(nil)
	for _, tc := range []struct {
		tag  string
		key  []byte
		want KeyUse
	}{
		{"v0.1.0-beta.2", legacy, KeyLegacy},
		{"v0.4.0-beta.2", legacy, KeyLegacy},
		{"v0.4.0-beta.3", legacy, KeyRefused},
		{"v0.4.0", legacy, KeyRefused},
		// New tags sorting at or below the last legacy release are refused for
		// every key, so they cannot be legacy-signed and then fail repair.
		{"v0.2.0", legacy, KeyRefused},
		{"v0.3.0-beta.1", legacy, KeyRefused},
		{"v0.4.0-alpha.1", legacy, KeyRefused},
		{"v0.4.0-beta", a, KeyRefused},
		{"v0.4.0-RC.1", a, KeyRefused},
		{"v0.3.1", other, KeyRefused},
		{"v0.4.0-beta.3", a, KeyHardware},
		{"v0.4.0", b, KeyHardware},
		{"v0.4.0-beta.2", a, KeyRefused},
		{"v0.2.0", b, KeyRefused},
		{"v0.4.0-beta.3", other, KeyUnpinned},
		{"v0.1.0-beta.2", other, KeyUnpinned},
	} {
		got, err := SigningKeyUse(tc.tag, tc.key)
		if got != tc.want || (tc.want == KeyRefused) != (err != nil) {
			t.Fatalf("%s %s: got %v, %v; want %v", tc.tag, KeyID(tc.key), got, err, tc.want)
		}
	}
	if _, err := SigningKeyUse("latest", a); err == nil {
		t.Fatal("accepted an invalid tag")
	}
	for _, tag := range LegacyReleaseTags {
		if c, err := CompareVersions(tag, LastLegacyTag); err != nil || c > 0 {
			t.Fatalf("legacy tag %s sorts after %s", tag, LastLegacyTag)
		}
	}
	if LegacyReleaseTags[len(LegacyReleaseTags)-1] != LastLegacyTag {
		t.Fatal("LastLegacyTag must be the last legacy release")
	}
}

func TestStrictVersionSyntax(t *testing.T) {
	for _, v := range []string{"v0.4.0-beta.02", "v0.04.0", "v00.4.0", "v0.4.00", "v0.4.0-beta..3", "v0.4.0-", "v0.4.0-beta.3.", "v0.4.0-.beta", "v0.4.0+build", "v0.4.0-beta_3"} {
		if _, err := CompareVersions(v, "v0.4.0"); err == nil {
			t.Fatalf("accepted %s", v)
		}
		if _, err := SigningKeyUse(v, DecodedHardwareReleaseKeys()[0]); err == nil {
			t.Fatalf("signing policy accepted %s", v)
		}
	}
	for _, v := range []string{"v0.4.0-0", "v1.0.0-0a", "v1.0.0-x-y.7", "1.10.0-rc.1"} {
		if _, err := CompareVersions(v, "v0.4.0"); err != nil {
			t.Fatalf("rejected valid %s: %v", v, err)
		}
	}
}
