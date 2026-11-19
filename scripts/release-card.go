//go:build ignore

// Release signing key ceremony helper for OpenPGP hardware tokens (YubiKey).
//
// Usage:
//
//	go run scripts/release-card.go list
//	go run scripts/release-card.go info     -serial N
//	go run scripts/release-card.go probe    -serial N
//	go run scripts/release-card.go generate -serial N -touch fixed
//	go run scripts/release-card.go pubkey   -serial N
//	go run scripts/release-card.go selftest -serial N -pubkey BASE64 -out DIR
//
// PINs are read from the console without echo and never printed. Only public
// data is written.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"bimeron/internal/releasecard"

	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	serial := fs.Uint("serial", 0, "OpenPGP card serial number")
	touch := fs.String("touch", "fixed", "touch policy for generate: on or fixed")
	pub := fs.String("pubkey", "", "expected base64 Ed25519 public key for selftest")
	out := fs.String("out", "", "directory for selftest evidence (public data only)")
	fs.Parse(os.Args[2:])
	var err error
	switch cmd {
	case "list":
		err = list()
	case "info":
		err = withCard(*serial, info)
	case "probe":
		err = withCard(*serial, probe)
	case "pubkey":
		err = withCard(*serial, pubkey)
	case "generate":
		err = generate(*serial, *touch)
	case "selftest":
		err = selftest(*serial, *pub, *out)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: release-card list | info|probe|pubkey -serial N | generate -serial N -touch on|fixed | selftest -serial N -pubkey B64 -out DIR")
	os.Exit(2)
}

func withCard(serial uint, f func(*releasecard.Card) error) error {
	if serial == 0 {
		return errors.New("-serial is required")
	}
	c, err := releasecard.Open(uint32(serial))
	if err != nil {
		return err
	}
	defer c.Close()
	return f(c)
}

func list() error {
	refs, err := releasecard.List()
	if err != nil {
		return err
	}
	if len(refs) == 0 {
		fmt.Println("no OpenPGP cards found")
	}
	for _, r := range refs {
		fmt.Printf("serial %d\t%s\n", r.Serial, r.Reader)
	}
	return nil
}

func info(c *releasecard.Card) error {
	i := c.Info()
	fmt.Printf("serial:            %d\n", i.Serial)
	fmt.Printf("manufacturer:      %04X\n", i.Manufacturer)
	fmt.Printf("OpenPGP version:   %d.%d\n", i.Version[0], i.Version[1])
	fmt.Printf("sig attributes:    %s (ed25519=%v)\n", hex.EncodeToString(i.SigAttributes), i.SigIsEd25519())
	if i.SigSlotEmpty() {
		fmt.Println("sig key:           none")
	} else {
		fmt.Printf("sig fingerprint:   %X\n", i.SigFingerprint)
		fmt.Printf("sig created:       %s\n", time.Unix(int64(i.SigCreated), 0).UTC().Format(time.RFC3339))
	}
	if i.SigTouchKnown {
		fmt.Printf("sig touch policy:  %s\n", i.SigTouch)
	}
	fmt.Printf("PIN valid for:     %s\n", map[bool]string{false: "one signature", true: "several signatures"}[i.PW1Multiple])
	fmt.Printf("PIN tries left:    %d (reset code %d, admin PIN %d)\n", i.PW1Retries, i.ResetRetries, i.PW3Retries)
	fmt.Printf("extended APDU max: command %d, response %d\n", i.MaxCommand, i.MaxResponse)
	if !i.SigSlotEmpty() && i.SigIsEd25519() {
		return pubkey(c)
	}
	return nil
}

func probe(c *releasecard.Card) error {
	fmt.Println("Unauthenticated signature length probe; 6982 = length accepted, PIN required.")
	for _, n := range []int{32, 255, 256, 1024, 1500, 2048, 3000, 4096} {
		sw, err := c.ProbeSignLength(n)
		if err != nil {
			fmt.Printf("%5d bytes: %v\n", n, err)
			continue
		}
		fmt.Printf("%5d bytes: %04X\n", n, sw)
	}
	return nil
}

func pubkey(c *releasecard.Card) error {
	pub, err := c.SigningPublicKey()
	if err != nil {
		return err
	}
	fmt.Printf("public key (base64): %s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("key_id:              %s\n", releasecard.KeyID(pub))
	return nil
}

func readSecret(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("PIN entry requires an interactive console")
	}
	fmt.Fprint(os.Stderr, prompt)
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, errors.New("empty PIN")
	}
	return p, nil
}

func confirm(prompt, want string) error {
	fmt.Fprint(os.Stderr, prompt)
	var got string
	fmt.Fscanln(os.Stdin, &got)
	if strings.TrimSpace(got) != want {
		return errors.New("not confirmed; nothing changed")
	}
	return nil
}

// generate shows the planned change and reads the confirmation and admin PIN
// with no card session open, then reconnects and performs every card step at
// once, so an idle PC/SC transaction cannot be reset while the user types.
func generate(serial uint, touchName string) error {
	touch, err := releasecard.ParseTouchPolicy(touchName)
	if err != nil {
		return err
	}
	if serial == 0 {
		return errors.New("-serial is required")
	}
	var before releasecard.Info
	if err := withCard(serial, func(c *releasecard.Card) error { before = *c.Info(); return nil }); err != nil {
		return err
	}
	i := &before
	if !i.SigSlotEmpty() {
		return fmt.Errorf("%w (fingerprint %X); refusing to replace it", releasecard.ErrSlotOccupied, i.SigFingerprint)
	}
	fmt.Fprintf(os.Stderr, "Card %d, OpenPGP application, signature (SIG) slot only:\n", i.Serial)
	fmt.Fprintf(os.Stderr, "  algorithm attributes: %s -> Ed25519 (%x)\n", hex.EncodeToString(i.SigAttributes), releasecard.Ed25519Attributes)
	fmt.Fprintf(os.Stderr, "  touch policy:         %s -> %s\n", i.SigTouch, touch)
	fmt.Fprintln(os.Stderr, "  key:                  none -> new Ed25519 key generated on the card (not exportable)")
	if touch == releasecard.TouchFixed {
		fmt.Fprintln(os.Stderr, "  'fixed' cannot be turned off later without resetting the OpenPGP application.")
	}
	fmt.Fprintln(os.Stderr, "Nothing else changes: PIV, FIDO, OTP, PINs and the other OpenPGP slots stay as they are.")
	fmt.Fprintf(os.Stderr, "Admin PIN tries left: %d. A wrong admin PIN uses one try.\n", i.PW3Retries)
	if err := confirm(fmt.Sprintf("Type the serial %d to continue: ", i.Serial), strconv.FormatUint(uint64(i.Serial), 10)); err != nil {
		return err
	}
	pin, err := readSecret("Admin PIN: ")
	if err != nil {
		return err
	}
	defer clear(pin)
	return withCard(serial, func(c *releasecard.Card) error {
		if !c.Info().SigSlotEmpty() {
			return releasecard.ErrSlotOccupied
		}
		if err := c.VerifyAdminPIN(pin); err != nil {
			return err
		}
		pub, err := c.GenerateSigningKey(touch, time.Now())
		if err != nil {
			return err
		}
		fmt.Println("generated.")
		fmt.Printf("sig fingerprint:     %X\n", c.Info().SigFingerprint)
		fmt.Printf("touch policy:        %s\n", c.Info().SigTouch)
		fmt.Printf("public key (base64): %s\n", base64.StdEncoding.EncodeToString(pub))
		fmt.Printf("key_id:              %s\n", releasecard.KeyID(pub))
		return nil
	})
}

// selftest signs manifest-shaped messages, including one of the maximum
// supported size, and verifies each signature with crypto/ed25519, the same
// primitive the update verifiers use.
func selftest(serial uint, pubB64, out string) error {
	if serial == 0 || pubB64 == "" || out == "" {
		return errors.New("-serial, -pubkey and -out are required")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(pubB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("-pubkey must be a base64 32-byte Ed25519 public key")
	}
	want := ed25519.PublicKey(raw)
	if err := releasecard.CheckSigner(uint32(serial), want, nil); err != nil {
		return err
	}
	dir := filepath.Join(out, fmt.Sprintf("selftest-%d-%s", serial, releasecard.KeyID(want)))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	secret, err := readSecret("Signing PIN: ")
	if err != nil {
		return err
	}
	defer clear(secret)
	pin := func() ([]byte, error) { return append([]byte(nil), secret...), nil }
	for _, n := range []int{1200, releasecard.MaxManifestSize} {
		msg := testManifest(n)
		sig, err := releasecard.SignManifest(uint32(serial), want, msg, pin, func() { fmt.Fprintf(os.Stderr, "Touch the YubiKey to sign %d bytes...\n", n) })
		if err != nil {
			return fmt.Errorf("%d-byte message: %w", n, err)
		}
		name := filepath.Join(dir, fmt.Sprintf("manifest-%d.json", n))
		if err := os.WriteFile(name, msg, 0644); err != nil {
			return err
		}
		if err := os.WriteFile(name+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0644); err != nil {
			return err
		}
		fmt.Printf("%d bytes: signature verified\n", n)
	}
	note := fmt.Sprintf("card serial: %d\npublic key: %s\nkey_id: %s\n", serial, pubB64, releasecard.KeyID(want))
	return os.WriteFile(filepath.Join(dir, "README.txt"), []byte(note), 0644)
}

// testManifest returns an n-byte JSON document ending in LF that is clearly
// not a release manifest.
func testManifest(n int) []byte {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	head := fmt.Sprintf("{\n  \"purpose\": \"bimeron release key self-test, not a release\",\n  \"nonce\": \"%x\",\n  \"padding\": \"", nonce)
	tail := "\"\n}\n"
	pad := n - len(head) - len(tail)
	return []byte(head + strings.Repeat("x", pad) + tail)
}
