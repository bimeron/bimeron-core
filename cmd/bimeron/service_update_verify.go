package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bimeron/internal/control"
)

type updateExpectation struct {
	source, version, sha256 string
	// keepKillSwitch asks the installed service to keep kill switch
	// protection across the update (ADR 0041, Windows only).
	keepKillSwitch bool
}

func parseUpdateExpectation(args []string) (updateExpectation, error) {
	f := flag.NewFlagSet("service update", flag.ContinueOnError)
	version := f.String("version", "", "expected core version")
	digest := f.String("sha256", "", "expected executable SHA-256")
	source := f.String("source", "", "downloaded executable path")
	keep := f.Bool("keep-kill-switch", false, "keep kill switch protection installed while the service is replaced (Windows)")
	if err := f.Parse(args); err != nil {
		return updateExpectation{}, err
	}
	if f.NArg() != 0 || *version == "" || len(*digest) != 64 || !filepath.IsAbs(*source) {
		return updateExpectation{}, fmt.Errorf("usage: service update -source <absolute-path> -version <version> -sha256 <executable-sha256> [-keep-kill-switch]")
	}
	if _, err := hex.DecodeString(*digest); err != nil {
		return updateExpectation{}, fmt.Errorf("invalid SHA-256: %w", err)
	}
	return updateExpectation{source: *source, version: *version, sha256: strings.ToLower(*digest), keepKillSwitch: *keep}, nil
}

var errNotRegularFile = errors.New("not a regular file")

// regularFileSHA256 returns the hex SHA-256 digest of a regular file.
func regularFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", errNotRegularFile
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifyUpdateFile(path, want string) error {
	got, err := regularFileSHA256(path)
	if errors.Is(err, errNotRegularFile) {
		return fmt.Errorf("update is not a regular file")
	}
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("staged executable SHA-256 mismatch")
	}
	return nil
}

// Release executables are tens of MiB; the bound keeps a bad source from
// filling the system volume. Tests lower it.
var maxUpdateSourceSize int64 = 256 << 20

var (
	errUpdateSourceNotRegular = errors.New("update source must be a regular file")
	errUpdateSourceLink       = errors.New("update source must be the file itself, not a symbolic link or junction")
)

// copyUpdateData copies at most maxUpdateSourceSize bytes, then syncs and closes out.
func copyUpdateData(out *os.File, in io.Reader) error {
	n, err := io.Copy(out, io.LimitReader(in, maxUpdateSourceSize+1))
	if err == nil && n > maxUpdateSourceSize {
		err = fmt.Errorf("update source exceeds %d bytes", maxUpdateSourceSize)
	}
	if err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	return err
}

// removeStagedUpdate deletes a leftover staged file and reports a failed removal.
func removeStagedUpdate(staged string, err *error) {
	if removeErr := os.Remove(staged); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
		*err = errors.Join(*err, fmt.Errorf("remove staged update: %w", removeErr))
	}
}

// stageVerifiedUpdate verifies the staged copy, not the source, and removes it
// on failure.
func stageVerifiedUpdate(source, staged, wantSHA256 string, copyFile func(string, string) error) (err error) {
	if err = copyFile(source, staged); err == nil {
		err = verifyUpdateFile(staged, wantSHA256)
	}
	if err != nil {
		removeStagedUpdate(staged, &err)
	}
	return err
}

func waitUpdatedServiceContext(parent context.Context, wantVersion string) error {
	return waitUpdatedServiceWithCall(parent, wantVersion, control.CallService)
}
func waitUpdatedServiceWithCall(parent context.Context, wantVersion string, call func(context.Context, control.Request) (control.Response, error)) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	var last error
	for ctx.Err() == nil {
		probe, probeCancel := context.WithTimeout(ctx, 2*time.Second)
		err := verifyServiceReadiness(probe, call, func(hello control.Response) error {
			return validateUpdatedHello(hello, wantVersion)
		})
		probeCancel()
		if err == nil {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.Join(fmt.Errorf("updated service IPC health check failed"), last, ctx.Err())
}

func validateUpdatedHello(a control.Response, wantVersion string) error {
	if a.Error != "" || a.Version != control.Version || a.Core == nil || a.Core.Version != wantVersion {
		reported := "none"
		if a.Core != nil {
			reported = shown(a.Core.Version)
		}
		return fmt.Errorf("service reported core %s and protocol %d, expected %s and %d", reported, a.Version, wantVersion, control.Version)
	}
	return nil
}
