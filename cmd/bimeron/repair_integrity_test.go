package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRepairPayloadIntegrityAndRollback(t *testing.T) {
	source, err := protectedSelfUpdate()
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(source.source)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"exact", "xor", "zero-header", "missing"} {
		for _, fail := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/ready", true: "/rollback"}[fail], func(t *testing.T) {
				target := filepath.Join(t.TempDir(), "core")
				data := bytes.Clone(original)
				switch kind {
				case "xor":
					for i := 0x1000; i < 0x1200; i++ {
						data[i] ^= 0xff
					}
				case "zero-header":
					clear(data[:4096])
				}
				if kind != "missing" {
					if err := os.WriteFile(target, data, 0700); err != nil {
						t.Fatal(err)
					}
				}
				differs, err := repairPayloadDiffers(target)
				if err != nil || differs != (kind != "exact") {
					t.Fatal(differs, err)
				}
				if !differs {
					return
				}
				deactivated := false
				err = repairDamagedPayload(context.Background(), target, func(src, dst string) error {
					b, e := os.ReadFile(src)
					if e != nil {
						return e
					}
					return os.WriteFile(dst, b, 0700)
				}, func(context.Context) error {
					if err := verifyUpdateFile(target, source.sha256); err != nil {
						t.Fatal(err)
					}
					if fail {
						return errors.New("readiness rejected")
					}
					return nil
				}, func(context.Context) error { deactivated = true; return nil })
				if (err != nil) != fail || deactivated != fail {
					t.Fatal(err, deactivated)
				}
				got, e := os.ReadFile(target)
				if fail && kind == "missing" {
					if !os.IsNotExist(e) {
						t.Fatal(e)
					}
					return
				}
				want := original
				if fail {
					want = data
				}
				if e != nil || !bytes.Equal(got, want) {
					t.Fatal("incorrect committed/rolled back image", e)
				}
			})
		}
	}
}
