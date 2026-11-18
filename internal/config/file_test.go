package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bimeron/internal/problem"
)

// loadProblem writes profile into dir and returns the Load problem.
func loadProblem(t *testing.T, dir, profile string) *problem.Error {
	t.Helper()
	path := filepath.Join(dir, "profile.conf")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	p, ok := problem.As(err)
	if !ok {
		t.Fatalf("Load() = %v", err)
	}
	return p
}

func TestLoadRequiresRegularFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "large.key"), bytes.Repeat([]byte("a"), maxSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "folder")); problem.Of(err).Code != "file_not_regular" {
		t.Fatalf("Load(directory) = %v", err)
	}
	for _, tc := range []struct{ file, code string }{
		{"folder", "file_not_regular"},
		{"large.key", "file_too_large"},
		{"missing.key", "file_unreadable"},
	} {
		p := loadProblem(t, dir, "[Profile]\nVersion = 1\n\n[AccessKey]\nFile = "+tc.file+"\n")
		if p.Code != tc.code || p.Section != "AccessKey" || p.Source != "File" || p.Line != 5 {
			t.Errorf("File = %s: problem = %+v", tc.file, *p)
		}
		if strings.Contains(p.Message, dir) {
			t.Errorf("File = %s: message names the path: %q", tc.file, p.Message)
		}
	}
}
