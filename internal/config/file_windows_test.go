package config

import (
	"testing"

	"bimeron/internal/problem"
)

func TestLoadRequiresLocalPaths(t *testing.T) {
	for _, path := range []string{`\\server\share\profile.conf`, `\\.\pipe\bimeron-test`, `\\?\C:\profile.conf`, `C:\CON`} {
		if _, err := Load(path); problem.Of(err).Code != "file_path_not_local" {
			t.Errorf("Load(%q) = %v", path, err)
		}
	}
	dir := t.TempDir()
	for _, file := range []string{`\\server\share\proxy.key`, `\\.\pipe\bimeron-test`, `NUL`} {
		p := loadProblem(t, dir, "[Profile]\nVersion = 1\n\n[AccessKey]\nFile = "+file+"\n")
		if p.Code != "file_path_not_local" || p.Section != "AccessKey" || p.Source != "File" {
			t.Errorf("File = %s: problem = %+v", file, *p)
		}
	}
	p := loadProblem(t, dir, "[Profile]\nVersion = 1\n\n[AccessKey]\nSS = ss://aes-256-gcm:s@example.com:8388\n\n[GeoData]\nGeoSiteFile = \\\\server\\share\\geosite.dat\n\n[Rule]\nGeoSite = ru\nAction = direct\n")
	if p.Code != "geodata_unreadable" || p.Field != "GeoSiteFile" {
		t.Errorf("GeoSiteFile on a share: problem = %+v", *p)
	}
}
