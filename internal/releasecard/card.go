// Package releasecard signs release manifests with an Ed25519 key held in the
// OpenPGP application of a hardware token such as a YubiKey.
//
// The card computes a plain RFC 8032 Ed25519 (PureEdDSA) signature over the
// exact bytes it receives in PSO: COMPUTE DIGITAL SIGNATURE. This package sends
// the complete manifest bytes, so the result is the same 64-byte signature a
// software key would produce and existing verifiers need no change. No OpenPGP
// packets, hashes or prefixes are involved.
package releasecard

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"bimeron/release"
)

// Transport exchanges one raw APDU with a card.
type Transport interface {
	Transmit(command []byte) ([]byte, error)
}

var errNoReaders = errors.New("no smart card readers")

// Bounds for a chained (61xx) card response.
const (
	maxResponseChunks = 64
	maxResponseSize   = 65536
)

// MaxManifestSize is the largest manifest this package signs. YubiKey 5
// OpenPGP accepts at most 3070 bytes of PSO input; the bound keeps a margin so a
// growing manifest fails early in tests rather than at release time.
const MaxManifestSize = 2560

// ErrSlotOccupied reports that the signature slot already holds a key.
var ErrSlotOccupied = errors.New("the OpenPGP signature slot already holds a key")

var openPGPAID = []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}

// Ed25519Attributes is the OpenPGP algorithm attribute value for EdDSA over
// Ed25519 (algorithm 22, OID 1.3.6.1.4.1.11591.15.1).
var Ed25519Attributes = []byte{0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}

// StatusError is a card response status word other than 9000.
type StatusError struct {
	Op string
	SW uint16
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s: card status %04X (%s)", e.Op, e.SW, statusText(e.SW))
}

func statusText(sw uint16) string {
	switch {
	case sw == 0x6982:
		return "security status not satisfied: PIN not verified or touch not confirmed"
	case sw == 0x6983:
		return "PIN blocked"
	case sw&0xFFF0 == 0x63C0:
		return fmt.Sprintf("wrong PIN, %d tries left", sw&0x0F)
	case sw == 0x6700:
		return "wrong length"
	case sw == 0x6A80:
		return "incorrect data"
	case sw == 0x6A88:
		return "referenced data not found"
	case sw == 0x6985:
		return "conditions of use not satisfied"
	case sw == 0x6D00:
		return "instruction not supported"
	}
	return "unexpected status"
}

// TouchPolicy is the YubiKey user-interaction (touch) policy of a key slot.
type TouchPolicy byte

const (
	TouchOff         TouchPolicy = 0x00
	TouchOn          TouchPolicy = 0x01
	TouchFixed       TouchPolicy = 0x02
	TouchCached      TouchPolicy = 0x03
	TouchCachedFixed TouchPolicy = 0x04
)

func (p TouchPolicy) String() string {
	switch p {
	case TouchOff:
		return "off"
	case TouchOn:
		return "on"
	case TouchFixed:
		return "fixed"
	case TouchCached:
		return "cached"
	case TouchCachedFixed:
		return "cached-fixed"
	}
	return "unknown(" + strconv.Itoa(int(p)) + ")"
}

// ParseTouchPolicy accepts the policies that require a touch for every signature.
func ParseTouchPolicy(s string) (TouchPolicy, error) {
	switch s {
	case "on":
		return TouchOn, nil
	case "fixed":
		return TouchFixed, nil
	}
	return 0, fmt.Errorf("touch policy must be \"on\" or \"fixed\", got %q", s)
}

// Info is public, PIN-free metadata from the OpenPGP application.
type Info struct {
	Serial         uint32
	Manufacturer   uint16
	Version        [2]byte
	SigAttributes  []byte
	SigFingerprint [20]byte
	SigCreated     uint32
	PW1Multiple    bool
	PW1Retries     int
	ResetRetries   int
	PW3Retries     int
	MaxCommand     int
	MaxResponse    int
	SigTouch       TouchPolicy
	SigTouchKnown  bool
	// SigKeyStatus is the key information DO (0xDE) status of the signature
	// key: 0 absent, 1 generated on the card, 2 imported.
	SigKeyStatus      byte
	SigKeyStatusKnown bool
}

// SigSlotEmpty reports whether no signature key fingerprint is recorded.
func (i *Info) SigSlotEmpty() bool {
	return i.SigFingerprint == [20]byte{} && (!i.SigKeyStatusKnown || i.SigKeyStatus == 0)
}

// SigIsEd25519 reports whether the signature slot uses Ed25519 attributes.
func (i *Info) SigIsEd25519() bool {
	return bytes.Equal(bytes.TrimSuffix(i.SigAttributes, []byte{0xFF}), Ed25519Attributes)
}

// Card is a selected OpenPGP application session.
type Card struct {
	t      Transport
	closer func() error
	info   *Info
}

// NewCard selects the OpenPGP application on t and reads its metadata.
func NewCard(t Transport) (*Card, error) {
	c := &Card{t: t}
	if _, err := c.exchange("SELECT OpenPGP", 0x00, 0xA4, 0x04, 0x00, openPGPAID, 256, false); err != nil {
		return nil, err
	}
	info, err := c.readInfo()
	if err != nil {
		return nil, err
	}
	c.info = info
	return c, nil
}

// Close ends the session; the PC/SC transport resets the card.
func (c *Card) Close() error {
	if c.closer == nil {
		return nil
	}
	return c.closer()
}

// Info returns metadata read when the session opened or after the last change.
func (c *Card) Info() *Info { return c.info }

func (c *Card) exchange(op string, cla, ins, p1, p2 byte, data []byte, le int, extended bool) ([]byte, error) {
	var out []byte
	if !extended && len(data) > 255 {
		// Command chaining for short-APDU cards.
		for len(data) > 255 {
			resp, err := c.t.Transmit(encodeAPDU(cla|0x10, ins, p1, p2, data[:255], 0, false))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			if sw := statusWord(resp); sw != 0x9000 {
				return nil, &StatusError{op, sw}
			}
			data = data[255:]
		}
	}
	resp, err := c.t.Transmit(encodeAPDU(cla, ins, p1, p2, data, le, extended))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	for chunks := 0; ; chunks++ {
		if chunks > maxResponseChunks || len(out) > maxResponseSize {
			return nil, fmt.Errorf("%s: card response too long", op)
		}
		if len(resp) < 2 {
			return nil, fmt.Errorf("%s: short card response", op)
		}
		sw := statusWord(resp)
		out = append(out, resp[:len(resp)-2]...)
		switch {
		case sw == 0x9000:
			return out, nil
		case sw>>8 == 0x61:
			n := int(sw & 0xFF)
			if n == 0 {
				n = 256
			}
			resp, err = c.t.Transmit([]byte{0x00, 0xC0, 0x00, 0x00, byte(n)})
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
		default:
			return nil, &StatusError{op, sw}
		}
	}
}

func statusWord(resp []byte) uint16 {
	if len(resp) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(resp[len(resp)-2:])
}

// encodeAPDU builds an ISO 7816-4 command. le is the expected response length
// (0 for none, up to 256 short or 65536 extended).
func encodeAPDU(cla, ins, p1, p2 byte, data []byte, le int, extended bool) []byte {
	cmd := []byte{cla, ins, p1, p2}
	if extended {
		if len(data) > 0 {
			cmd = append(cmd, 0x00, byte(len(data)>>8), byte(len(data)))
			cmd = append(cmd, data...)
			if le > 0 {
				cmd = append(cmd, byte(le>>8), byte(le))
			}
		} else if le > 0 {
			cmd = append(cmd, 0x00, byte(le>>8), byte(le))
		}
		return cmd
	}
	if len(data) > 0 {
		cmd = append(cmd, byte(len(data)))
		cmd = append(cmd, data...)
	}
	if le > 0 {
		cmd = append(cmd, byte(le))
	}
	return cmd
}

func (c *Card) getData(tag uint16) ([]byte, error) {
	return c.exchange(fmt.Sprintf("GET DATA %04X", tag), 0x00, 0xCA, byte(tag>>8), byte(tag), nil, 256, false)
}

func (c *Card) readInfo() (*Info, error) {
	raw, err := c.getData(0x006E)
	if err != nil {
		return nil, err
	}
	tlvs, err := parseTLV(raw)
	if err != nil {
		return nil, err
	}
	i := &Info{}
	aid := findTag(tlvs, 0x4F)
	if len(aid) != 16 || !bytes.Equal(aid[:6], openPGPAID) {
		return nil, errors.New("unexpected OpenPGP application identifier")
	}
	copy(i.Version[:], aid[6:8])
	i.Manufacturer = binary.BigEndian.Uint16(aid[8:10])
	i.Serial = bcdSerial(aid[10:14])
	i.SigAttributes = append([]byte(nil), findTag(tlvs, 0xC1)...)
	if fp := findTag(tlvs, 0xC5); len(fp) >= 20 {
		copy(i.SigFingerprint[:], fp[:20])
	}
	if ts := findTag(tlvs, 0xCD); len(ts) >= 4 {
		i.SigCreated = binary.BigEndian.Uint32(ts[:4])
	}
	pw := findTag(tlvs, 0xC4)
	if len(pw) < 7 {
		return nil, errors.New("missing PIN status bytes")
	}
	i.PW1Multiple = pw[0] != 0
	i.PW1Retries, i.ResetRetries, i.PW3Retries = int(pw[4]), int(pw[5]), int(pw[6])
	if ext := findTag(tlvs, 0x7F66); len(ext) > 0 {
		if inner, err := parseTLV(ext); err == nil {
			var ints []int
			for _, t := range inner {
				if t.tag == 0x02 && len(t.value) == 2 {
					ints = append(ints, int(binary.BigEndian.Uint16(t.value)))
				}
			}
			if len(ints) == 2 {
				i.MaxCommand, i.MaxResponse = ints[0], ints[1]
			}
		}
	}
	if ki, err := c.getData(0x00DE); err == nil {
		i.SigKeyStatus, i.SigKeyStatusKnown = parseKeyInformation(ki)
	}
	if uif, err := c.getData(0x00D6); err == nil && len(uif) >= 1 {
		i.SigTouch, i.SigTouchKnown = TouchPolicy(uif[0]), true
	}
	return i, nil
}

// parseKeyInformation returns the signature key status from the key
// information DO: (key reference, status) pairs, optionally inside a DE tag.
// Anything malformed reports the status as unknown, so callers fall back to
// READ PUBLIC KEY.
func parseKeyInformation(b []byte) (byte, bool) {
	if len(b) >= 2 && b[0] == 0xDE {
		if int(b[1]) != len(b)-2 {
			return 0, false
		}
		b = b[2:]
	}
	if len(b) == 0 || len(b)%2 != 0 {
		return 0, false
	}
	for j := 0; j < len(b); j += 2 {
		if b[j] == 0x01 {
			return b[j+1], true
		}
	}
	return 0, false
}

// bcdSerial decodes the card serial; YubiKeys store their decimal serial as BCD.
func bcdSerial(b []byte) uint32 {
	if n, err := strconv.ParseUint(hex.EncodeToString(b), 10, 32); err == nil {
		return uint32(n)
	}
	return binary.BigEndian.Uint32(b)
}

type tlv struct {
	tag   uint16
	value []byte
	inner []tlv
}

func parseTLV(b []byte) ([]tlv, error) {
	var out []tlv
	for len(b) > 0 {
		if b[0] == 0x00 || b[0] == 0xFF {
			b = b[1:]
			continue
		}
		tag := uint16(b[0])
		constructed := b[0]&0x20 != 0
		b = b[1:]
		if tag&0x1F == 0x1F {
			if len(b) == 0 {
				return nil, errors.New("truncated TLV tag")
			}
			tag = tag<<8 | uint16(b[0])
			b = b[1:]
		}
		if len(b) == 0 {
			return nil, errors.New("truncated TLV length")
		}
		n := int(b[0])
		b = b[1:]
		switch n {
		case 0x81:
			if len(b) < 1 {
				return nil, errors.New("truncated TLV length")
			}
			n, b = int(b[0]), b[1:]
		case 0x82:
			if len(b) < 2 {
				return nil, errors.New("truncated TLV length")
			}
			n, b = int(binary.BigEndian.Uint16(b)), b[2:]
		default:
			if n > 0x7F {
				return nil, errors.New("unsupported TLV length")
			}
		}
		if len(b) < n {
			return nil, errors.New("truncated TLV value")
		}
		t := tlv{tag: tag, value: b[:n]}
		if constructed {
			inner, err := parseTLV(t.value)
			if err != nil {
				return nil, err
			}
			t.inner = inner
		}
		out = append(out, t)
		b = b[n:]
	}
	return out, nil
}

func findTag(tlvs []tlv, tag uint16) []byte {
	for _, t := range tlvs {
		if t.tag == tag {
			return t.value
		}
		if v := findTag(t.inner, tag); v != nil {
			return v
		}
	}
	return nil
}

// SigningPublicKey reads the public key of the signature slot.
func (c *Card) SigningPublicKey() (ed25519.PublicKey, error) {
	if !c.info.SigIsEd25519() {
		return nil, errors.New("the signature slot is not configured for Ed25519")
	}
	resp, err := c.exchange("READ PUBLIC KEY", 0x00, 0x47, 0x81, 0x00, []byte{0xB6, 0x00}, 256, false)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(resp)
}

func parsePublicKey(resp []byte) (ed25519.PublicKey, error) {
	tlvs, err := parseTLV(resp)
	if err != nil {
		return nil, err
	}
	point := findTag(tlvs, 0x86)
	if len(point) == ed25519.PublicKeySize+1 && point[0] == 0x40 {
		point = point[1:]
	}
	if len(point) != ed25519.PublicKeySize {
		return nil, errors.New("card returned a malformed Ed25519 public key")
	}
	return ed25519.PublicKey(append([]byte(nil), point...)), nil
}

// VerifySigningPIN presents PW1 for signing. The caller owns and wipes pin.
func (c *Card) VerifySigningPIN(pin []byte) error {
	return pinError(c.verify("VERIFY PIN", 0x81, pin), "PIN")
}

// VerifyAdminPIN presents PW3. The caller owns and wipes pin.
func (c *Card) VerifyAdminPIN(pin []byte) error {
	return pinError(c.verify("VERIFY Admin PIN", 0x83, pin), "admin PIN")
}

// verify sends VERIFY and wipes the command buffer that held the PIN.
func (c *Card) verify(op string, ref byte, pin []byte) error {
	if len(pin) == 0 || len(pin) > 127 {
		return fmt.Errorf("%s: PIN length out of range", op)
	}
	cmd := encodeAPDU(0x00, 0x20, 0x00, ref, pin, 0, false)
	resp, err := c.t.Transmit(cmd)
	clear(cmd)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if sw := statusWord(resp); len(resp) < 2 || sw != 0x9000 {
		return &StatusError{op, sw}
	}
	return nil
}

// ErrWrongPIN reports a rejected PIN. YubiKeys answer 6982 rather than 63Cx.
var ErrWrongPIN = errors.New("wrong PIN")

func pinError(err error, name string) error {
	var se *StatusError
	if errors.As(err, &se) && (se.SW == 0x6982 || se.SW&0xFFF0 == 0x63C0) {
		return fmt.Errorf("%w: the card rejected the %s (status %04X); one try was used", ErrWrongPIN, name, se.SW)
	}
	return err
}

func (c *Card) useExtended(n int) bool {
	return n > 255 && c.info.MaxCommand >= n
}

// Sign asks the card for a raw Ed25519 signature over msg. The signing PIN
// must already be verified; a touch may be required.
func (c *Card) Sign(msg []byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, errors.New("empty message")
	}
	sig, err := c.exchange("PSO: COMPUTE DIGITAL SIGNATURE", 0x00, 0x2A, 0x9E, 0x9A, msg, 256, c.useExtended(len(msg)))
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("card returned a %d-byte signature, want %d", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

// ProbeSignLength sends an unauthenticated signature command carrying n bytes
// and returns the status word. It never verifies a PIN, so it cannot change PIN
// counters; 6982 means the length was accepted up to the PIN check.
func (c *Card) ProbeSignLength(n int) (uint16, error) {
	msg := make([]byte, n)
	_, err := c.exchange("PSO probe", 0x00, 0x2A, 0x9E, 0x9A, msg, 256, c.useExtended(n))
	var se *StatusError
	if errors.As(err, &se) {
		return se.SW, nil
	}
	if err != nil {
		return 0, err
	}
	return 0x9000, nil
}

// GenerateSigningKey creates a new non-exportable Ed25519 key in the empty
// signature slot, sets the touch policy, and records the OpenPGP fingerprint
// and creation time. The admin PIN must already be verified. It refuses to
// replace an existing key.
func (c *Card) GenerateSigningKey(touch TouchPolicy, created time.Time) (ed25519.PublicKey, error) {
	if !c.info.SigSlotEmpty() {
		return nil, ErrSlotOccupied
	}
	if !c.info.SigKeyStatusKnown {
		// Without the key information DO, require the card to report that no
		// signature public key exists before changing anything.
		_, err := c.exchange("READ PUBLIC KEY", 0x00, 0x47, 0x81, 0x00, []byte{0xB6, 0x00}, 256, false)
		var se *StatusError
		if err == nil {
			return nil, ErrSlotOccupied
		}
		if !errors.As(err, &se) || se.SW != 0x6A88 {
			return nil, fmt.Errorf("cannot confirm that the signature slot is empty: %w", err)
		}
	}
	if touch != TouchOn && touch != TouchFixed {
		return nil, errors.New("touch policy must require a touch for every signature")
	}
	if !c.info.SigIsEd25519() {
		if _, err := c.exchange("PUT DATA algorithm attributes", 0x00, 0xDA, 0x00, 0xC1, Ed25519Attributes, 0, false); err != nil {
			return nil, err
		}
	}
	resp, err := c.exchange("GENERATE KEY", 0x00, 0x47, 0x80, 0x00, []byte{0xB6, 0x00}, 256, false)
	if err != nil {
		return nil, err
	}
	pub, err := parsePublicKey(resp)
	if err != nil {
		return nil, err
	}
	ts := uint32(created.Unix())
	fp := OpenPGPFingerprint(pub, ts)
	if _, err := c.exchange("PUT DATA fingerprint", 0x00, 0xDA, 0x00, 0xC7, fp[:], 0, false); err != nil {
		return nil, err
	}
	var tsb [4]byte
	binary.BigEndian.PutUint32(tsb[:], ts)
	if _, err := c.exchange("PUT DATA creation time", 0x00, 0xDA, 0x00, 0xCE, tsb[:], 0, false); err != nil {
		return nil, err
	}
	// YubiKeys reset the touch policy when a key is generated, so set it last.
	if _, err := c.exchange("PUT DATA touch policy", 0x00, 0xDA, 0x00, 0xD6, []byte{byte(touch), 0x20}, 0, false); err != nil {
		return nil, err
	}
	info, err := c.readInfo()
	if err != nil {
		return nil, err
	}
	c.info = info
	if !info.SigTouchKnown || info.SigTouch != touch {
		return pub, fmt.Errorf("touch policy reads back as %s, want %s", info.SigTouch, touch)
	}
	return pub, nil
}

// OpenPGPFingerprint is the v4 fingerprint of an EdDSA (Ed25519) public key
// packet, recorded on the card so OpenPGP tools can identify the key.
func OpenPGPFingerprint(pub ed25519.PublicKey, created uint32) [20]byte {
	body := []byte{0x04, byte(created >> 24), byte(created >> 16), byte(created >> 8), byte(created), 0x16, 0x09}
	body = append(body, Ed25519Attributes[1:]...)
	body = append(body, 0x01, 0x07, 0x40)
	body = append(body, pub...)
	h := sha1.New()
	h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
	h.Write(body)
	var fp [20]byte
	copy(fp[:], h.Sum(nil))
	return fp
}

// CheckSize rejects a manifest larger than MaxManifestSize.
func CheckSize(n int) error {
	if n > MaxManifestSize {
		return fmt.Errorf("manifest is %d bytes; hardware release signing supports at most %d bytes", n, MaxManifestSize)
	}
	return nil
}

// KeyID is the release manifest key identifier: the first eight bytes of the
// SHA-256 of the public key, as 16 lowercase hex digits.
func KeyID(pub ed25519.PublicKey) string { return release.KeyID(pub) }

// CardRef names a reader holding an OpenPGP card.
type CardRef struct {
	Reader string
	Serial uint32
}

// List returns readers that hold an OpenPGP application.
func List() ([]CardRef, error) {
	ctx, err := openContext()
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	readers, err := ctx.Readers()
	if err != nil {
		return nil, err
	}
	var refs []CardRef
	for _, r := range readers {
		h, err := ctx.Connect(r)
		if err != nil {
			continue
		}
		c, err := NewCard(h)
		if err == nil {
			refs = append(refs, CardRef{r, c.info.Serial})
		}
		h.Leave()
	}
	return refs, nil
}

// openCard is replaced in tests.
var openCard = Open

// Open connects to the OpenPGP card with the given serial number. Keep the
// session short: Windows may end an idle PC/SC transaction after a few seconds
// and another program can then reset the card, so never wait for user input
// while a card is open.
func Open(serial uint32) (*Card, error) {
	ctx, err := openContext()
	if err != nil {
		return nil, err
	}
	readers, err := ctx.Readers()
	if err != nil {
		ctx.Close()
		return nil, err
	}
	for _, r := range readers {
		h, err := ctx.Connect(r)
		if err != nil {
			continue
		}
		c, err := NewCard(h)
		if err == nil && c.info.Serial == serial {
			c.closer = func() error {
				err := h.Close()
				if cerr := ctx.Close(); err == nil {
					err = cerr
				}
				return err
			}
			return c, nil
		}
		h.Leave()
	}
	ctx.Close()
	return nil, fmt.Errorf("no OpenPGP card with serial %d is connected", serial)
}

// CheckSigner reports whether the card holding serial can sign msg with want.
func CheckSigner(serial uint32, want ed25519.PublicKey, msg []byte) error {
	c, err := openCard(serial)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.checkSigner(want, len(msg))
}

func (c *Card) checkSigner(want ed25519.PublicKey, n int) error {
	pub, err := c.SigningPublicKey()
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, want) {
		return fmt.Errorf("card %d holds key %s, not the configured key %s", c.info.Serial, KeyID(pub), KeyID(want))
	}
	if err := CheckSize(n); err != nil {
		return err
	}
	if c.info.MaxCommand > 0 && n > c.info.MaxCommand {
		return fmt.Errorf("manifest is %d bytes; the card accepts at most %d", n, c.info.MaxCommand)
	}
	return nil
}

// SignManifest signs msg with the card holding serial. It checks that the card
// holds want before asking for the PIN, reads the PIN with no card session
// open, then reconnects, checks again, verifies the PIN, calls touch just
// before the card waits for a touch, and verifies the returned signature.
func SignManifest(serial uint32, want ed25519.PublicKey, msg []byte, pin func() ([]byte, error), touch func()) ([]byte, error) {
	if err := CheckSigner(serial, want, msg); err != nil {
		return nil, err
	}
	p, err := pin()
	if err != nil {
		return nil, err
	}
	defer clear(p)
	c, err := openCard(serial)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := c.checkSigner(want, len(msg)); err != nil {
		return nil, err
	}
	if err := c.VerifySigningPIN(p); err != nil {
		return nil, err
	}
	if touch != nil {
		touch()
	}
	sig, err := c.Sign(msg)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(want, msg, sig) {
		return nil, errors.New("card signature does not verify")
	}
	return sig, nil
}
