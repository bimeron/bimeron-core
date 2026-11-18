//go:build linux || darwin

package config

import (
	"path/filepath"
	"testing"
	"time"

	"bimeron/internal/problem"
	"golang.org/x/sys/unix"
)

func TestLoadRejectsSpecialFilesWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Load(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if problem.Of(err).Code != "file_not_regular" {
			t.Fatalf("Load(FIFO) = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Load(FIFO) blocked")
	}
	for _, file := range []string{fifo, "/dev/null", "/dev/zero"} {
		p := loadProblem(t, dir, "[Profile]\nVersion = 1\n\n[AccessKey]\nFile = "+file+"\n")
		if p.Code != "file_not_regular" || p.Section != "AccessKey" {
			t.Errorf("File = %s: problem = %+v", file, *p)
		}
	}
	p := loadProblem(t, dir, "[Profile]\nVersion = 1\n\n[AccessKey]\nSS = ss://aes-256-gcm:s@example.com:8388\n\n[GeoData]\nGeoIPFile = fifo\n\n[Rule]\nGeoIP = ru\nAction = direct\n")
	if p.Code != "geodata_unreadable" || p.Field != "GeoIPFile" {
		t.Errorf("GeoIPFile = fifo: problem = %+v", *p)
	}
}
