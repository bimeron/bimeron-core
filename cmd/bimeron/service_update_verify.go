package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bimeron/internal/control"
)

type updateExpectation struct{ source, version, sha256 string }

func parseUpdateExpectation(args []string) (updateExpectation, error) {
	f := flag.NewFlagSet("service update", flag.ContinueOnError)
	version := f.String("version", "", "expected core version")
	digest := f.String("sha256", "", "expected executable SHA-256")
	source := f.String("source", "", "downloaded executable path")
	if err := f.Parse(args); err != nil {
		return updateExpectation{}, err
	}
	if f.NArg() != 0 || *version == "" || len(*digest) != 64 || !filepath.IsAbs(*source) {
		return updateExpectation{}, fmt.Errorf("usage: service update -source <absolute-path> -version <version> -sha256 <executable-sha256>")
	}
	if _, err := hex.DecodeString(*digest); err != nil {
		return updateExpectation{}, fmt.Errorf("invalid SHA-256: %w", err)
	}
	return updateExpectation{*source, *version, strings.ToLower(*digest)}, nil
}

func verifyUpdateFile(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("update is not a regular file")
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return fmt.Errorf("staged executable SHA-256 mismatch")
	}
	return nil
}

func stageVerifiedUpdate(source, staged, wantSHA256 string, copyFile func(string, string) error) error {
	if err := copyFile(source, staged); err != nil {
		return err
	}
	return verifyUpdateFile(staged, wantSHA256)
}

func waitUpdatedService(wantVersion string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var last error
	for ctx.Err() == nil {
		probe, probeCancel := context.WithTimeout(ctx, 2*time.Second)
		a, err := control.CallService(probe, control.Request{Command: "hello"})
		probeCancel()
		if err == nil {
			err = validateUpdatedHello(a, wantVersion)
		}
		if err == nil {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.Join(fmt.Errorf("updated service IPC health check failed"), last)
}

func validateUpdatedHello(a control.Response, wantVersion string) error {
	if a.Error != "" || a.Version != control.Version || a.Core == nil || a.Core.Version != wantVersion {
		return fmt.Errorf("service reported core %v and protocol %d, expected %s and %d", a.Core, a.Version, wantVersion, control.Version)
	}
	return nil
}
