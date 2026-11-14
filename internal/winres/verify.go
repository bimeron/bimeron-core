package winres

import (
	"bytes"
	"debug/pe"
	"fmt"
)

// Verify checks that a linked executable carries the images of ico, in
// order and byte for byte, as icon group IconGroupID, and a VERSIONINFO with
// the Bimeron Core strings. If version is non-empty it must equal the file
// and product version text; otherwise any valid semantic or development
// version is accepted.
func Verify(f *pe.File, ico []byte, version string) error {
	want, err := ParseICO(ico)
	if err != nil {
		return err
	}
	resources, err := Read(f)
	if err != nil {
		return err
	}
	got, err := Icons(resources, IconGroupID)
	if err != nil {
		return err
	}
	if len(got) != len(want) {
		return fmt.Errorf("icon has %d images, want %d", len(got), len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Width != w.Width || g.Height != w.Height || g.BitCount != w.BitCount || !bytes.Equal(g.Data, w.Data) {
			return fmt.Errorf("icon image %d (%dx%d) differs from the source icon", i, w.Width, w.Height)
		}
	}
	var versionData []byte
	for _, r := range resources {
		if r.Type == TypeVersion && r.ID == VersionID {
			versionData = r.Data
		}
	}
	if versionData == nil {
		return fmt.Errorf("missing VERSIONINFO")
	}
	info, err := ParseVersionInfo(versionData)
	if err != nil {
		return err
	}
	text := info.Strings["ProductVersion"]
	if version != "" && text != version {
		return fmt.Errorf("VERSIONINFO product version %q, want %q", text, version)
	}
	v, err := ParseVersion(text)
	if text == DevVersion {
		v, err = ParseVersion("")
	}
	if err != nil {
		return fmt.Errorf("VERSIONINFO: %w", err)
	}
	if info.FileVersion != v.Fixed || info.ProductVersion != v.Fixed {
		return fmt.Errorf("VERSIONINFO numeric version %v does not match %q", info.FileVersion, text)
	}
	if (info.FileFlags&fixedPrerelease != 0) != v.Prerelease {
		return fmt.Errorf("VERSIONINFO prerelease flag does not match %q", text)
	}
	for _, kv := range versionStrings(v) {
		if info.Strings[kv[0]] != kv[1] {
			return fmt.Errorf("VERSIONINFO %s is %q, want %q", kv[0], info.Strings[kv[0]], kv[1])
		}
	}
	if info.Translation != [2]uint16{langEnglishUS, codepageUnicode} {
		return fmt.Errorf("VERSIONINFO translation %#v", info.Translation)
	}
	return nil
}
