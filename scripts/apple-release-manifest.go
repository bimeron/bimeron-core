//go:build ignore

// Standalone unsigned preparation / public-only verification. No signing mode.
package main

import (
	"bimeron/release/applemanifest"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func read(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Size() > max {
		return nil, errors.New("input is not a bounded regular file")
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if len(b) > int(max) {
		return nil, errors.New("input too large")
	}
	return b, e
}
func run() error {
	tag := flag.String("tag", "", "exact locally approved tag")
	rev := flag.String("revision", "", "exact locally approved full source revision")
	pubText := flag.String("public-key", "", "explicit base64 32-byte public key; identifier in preparation, independent trust in verification")
	dir := flag.String("dir", "release", "completed archive directory")
	policy := flag.String("compat", "release/apple-compatibility.json", "Apple compatibility policy")
	verify := flag.Bool("verify", false, "verify supplied manifest/signature and archives")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	pub, e := base64.StdEncoding.Strict().DecodeString(*pubText)
	if e != nil || len(pub) != 32 {
		return errors.New("explicit 32-byte public key required")
	}
	var verified applemanifest.VerifiedManifest
	if *verify {
		data, e := read(filepath.Join(*dir, applemanifest.ManifestName), applemanifest.MaxManifest)
		if e != nil {
			return e
		}
		sig, e := read(filepath.Join(*dir, applemanifest.ManifestName+".sig"), applemanifest.SignatureSize)
		if e != nil {
			return e
		}
		verified, e = applemanifest.VerifyManifest(data, sig, pub, *tag, *rev)
		if e != nil {
			return e
		}
	} else {
		// Validate untrusted identity before constructing local filenames.
		if len(*tag) < 2 || len(*tag) > 129 {
			return errors.New("invalid tag")
		}
		for _, r := range *tag {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
				return errors.New("invalid tag")
			}
		}
	}
	archives := map[string][]byte{}
	for _, arch := range []string{"amd64", "arm64"} {
		b, e := read(filepath.Join(*dir, "bimeron-"+*tag+"-macos-"+arch+".zip"), applemanifest.MaxArchive)
		if e != nil {
			return e
		}
		archives[arch] = b
	}
	if *verify {
		return verified.VerifyArchives(archives)
	}
	b, e := read(*policy, applemanifest.MaxManifest)
	if e != nil {
		return e
	}
	c, e := applemanifest.ParseCompatibility(b)
	if e != nil {
		return e
	}
	data, e := applemanifest.Prepare(*tag, *rev, c, pub, archives)
	if e != nil {
		return e
	}
	_, e = os.Stdout.Write(data)
	return e
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
