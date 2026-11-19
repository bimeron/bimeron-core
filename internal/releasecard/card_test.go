package releasecard

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeCard emulates the subset of a YubiKey 5 OpenPGP application used here.
type fakeCard struct {
	serial     [4]byte
	maxCommand int
	attrs      []byte
	fp         [20]byte
	created    [4]byte
	touch      byte
	priv       ed25519.PrivateKey
	pin, admin string
	pinOK      bool
	adminOK    bool
	pinTries   int
	adminTries int
	chain      []byte
	pending    []byte
	chained    int
	extended   int
}

func newFakeCard(maxCommand int) *fakeCard {
	return &fakeCard{
		serial: [4]byte{0x22, 0x33, 0x72, 0x46}, maxCommand: maxCommand,
		attrs: []byte{0x01, 0x08, 0x00, 0x00, 0x11, 0x00}, pin: "123456", admin: "12345678",
		pinTries: 3, adminTries: 3,
	}
}

func tlvBytes(tag uint16, value []byte) []byte {
	var out []byte
	if tag > 0xFF {
		out = append(out, byte(tag>>8))
	}
	out = append(out, byte(tag))
	switch n := len(value); {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xFF:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, value...)
}

func (f *fakeCard) appData() []byte {
	aid := append(append([]byte{}, openPGPAID...), 0x03, 0x04, 0x00, 0x06)
	aid = append(append(aid, f.serial[:]...), 0x00, 0x00)
	fps := append(append([]byte{}, f.fp[:]...), make([]byte, 40)...)
	times := append(append([]byte{}, f.created[:]...), make([]byte, 8)...)
	pw := []byte{0x01, 127, 127, 127, byte(f.pinTries), 0, byte(f.adminTries)}
	disc := tlvBytes(0xC0, make([]byte, 10))
	disc = append(disc, tlvBytes(0xC1, f.attrs)...)
	disc = append(disc, tlvBytes(0xC2, []byte{0x01, 0x08, 0x00, 0x00, 0x11, 0x00})...)
	disc = append(disc, tlvBytes(0xC3, []byte{0x01, 0x08, 0x00, 0x00, 0x11, 0x00})...)
	disc = append(disc, tlvBytes(0xC4, pw)...)
	disc = append(disc, tlvBytes(0xC5, fps)...)
	disc = append(disc, tlvBytes(0xC6, make([]byte, 60))...)
	disc = append(disc, tlvBytes(0xCD, times)...)
	body := tlvBytes(0x4F, aid)
	body = append(body, tlvBytes(0x5F52, make([]byte, 10))...)
	if f.maxCommand > 0 {
		ext := append(tlvBytes(0x02, []byte{byte(f.maxCommand >> 8), byte(f.maxCommand)}), tlvBytes(0x02, []byte{0x0B, 0xFE})...)
		body = append(body, tlvBytes(0x7F66, ext)...)
	}
	body = append(body, tlvBytes(0x73, disc)...)
	return tlvBytes(0x6E, body)
}

func sw(data []byte, w uint16) []byte { return append(append([]byte{}, data...), byte(w>>8), byte(w)) }

// respond splits long responses into 61xx chunks like a short-APDU card.
func (f *fakeCard) respond(data []byte) ([]byte, error) {
	if len(data) <= 256 {
		return sw(data, 0x9000), nil
	}
	f.pending = data[256:]
	n := len(f.pending)
	if n > 255 {
		n = 0
	}
	return sw(data[:256], 0x6100|uint16(n)), nil
}

func (f *fakeCard) Transmit(cmd []byte) ([]byte, error) {
	if len(cmd) < 4 {
		return sw(nil, 0x6700), nil
	}
	cla, ins, p1, p2 := cmd[0], cmd[1], cmd[2], cmd[3]
	body := cmd[4:]
	var data []byte
	switch {
	case len(body) <= 1:
	case body[0] == 0 && len(body) >= 3:
		if len(body) > 3 {
			n := int(binary.BigEndian.Uint16(body[1:3]))
			if len(body) < 3+n {
				return sw(nil, 0x6700), nil
			}
			data = body[3 : 3+n]
			f.extended++
		}
	default:
		n := int(body[0])
		if len(body) < 1+n {
			return sw(nil, 0x6700), nil
		}
		data = body[1 : 1+n]
	}
	if cla&0x10 != 0 {
		f.chain = append(f.chain, data...)
		f.chained++
		return sw(nil, 0x9000), nil
	}
	if f.chain != nil {
		data = append(f.chain, data...)
		f.chain = nil
	}
	if f.maxCommand > 0 && len(data) > f.maxCommand || len(data) > 3070 {
		return sw(nil, 0x6700), nil
	}
	switch ins {
	case 0xC0:
		out := f.pending
		f.pending = nil
		return f.respond(out)
	case 0xA4:
		return sw(nil, 0x9000), nil
	case 0xCA:
		switch uint16(p1)<<8 | uint16(p2) {
		case 0x006E:
			return f.respond(f.appData())
		case 0x00D6:
			return sw([]byte{f.touch, 0x20}, 0x9000), nil
		}
		return sw(nil, 0x6A88), nil
	case 0x20:
		want, ok, tries := f.pin, &f.pinOK, &f.pinTries
		if p2 == 0x83 {
			want, ok, tries = f.admin, &f.adminOK, &f.adminTries
		}
		if *tries == 0 {
			return sw(nil, 0x6983), nil
		}
		if string(data) != want {
			*tries--
			*ok = false
			return sw(nil, 0x6982), nil
		}
		*tries, *ok = 3, true
		return sw(nil, 0x9000), nil
	case 0xDA:
		if !f.adminOK {
			return sw(nil, 0x6982), nil
		}
		switch p2 {
		case 0xC1:
			f.attrs = append([]byte{}, data...)
		case 0xD6:
			f.touch = data[0]
		case 0xC7:
			copy(f.fp[:], data)
		case 0xCE:
			copy(f.created[:], data)
		}
		return sw(nil, 0x9000), nil
	case 0x47:
		if p1 == 0x80 {
			if !f.adminOK {
				return sw(nil, 0x6982), nil
			}
			_, f.priv, _ = ed25519.GenerateKey(rand.Reader)
			f.touch = 0 // YubiKeys reset the touch policy on generation.
		}
		if f.priv == nil {
			return sw(nil, 0x6A88), nil
		}
		return f.respond(tlvBytes(0x7F49, tlvBytes(0x86, f.priv.Public().(ed25519.PublicKey))))
	case 0x2A:
		if !f.pinOK {
			return sw(nil, 0x6982), nil
		}
		return f.respond(ed25519.Sign(f.priv, data))
	}
	return sw(nil, 0x6D00), nil
}

func generated(t *testing.T, f *fakeCard) (*Card, ed25519.PublicKey) {
	t.Helper()
	c, err := NewCard(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyAdminPIN([]byte(f.admin)); err != nil {
		t.Fatal(err)
	}
	pub, err := c.GenerateSigningKey(TouchFixed, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return c, pub
}

func TestGenerateSetsEd25519TouchAndFingerprint(t *testing.T) {
	f := newFakeCard(3070)
	c, pub := generated(t, f)
	i := c.Info()
	if i.Serial != 22337246 || !i.SigIsEd25519() || i.SigTouch != TouchFixed || i.SigCreated != 1700000000 {
		t.Fatalf("unexpected info %+v", i)
	}
	if i.SigFingerprint != OpenPGPFingerprint(pub, 1700000000) {
		t.Fatal("fingerprint not recorded")
	}
	got, err := c.SigningPublicKey()
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatal("public key read-back differs", err)
	}
	if _, err := c.GenerateSigningKey(TouchFixed, time.Now()); !errors.Is(err, ErrSlotOccupied) {
		t.Fatalf("replaced an existing key: %v", err)
	}
	if _, err := ParseTouchPolicy("off"); err == nil {
		t.Fatal("accepted a policy without touch")
	}
}

func TestSignFullManifestBytes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		maxCommand int
		extended   bool
	}{{"extended APDU", 3070, true}, {"command chaining", 0, false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeCard(tc.maxCommand)
			c, pub := generated(t, f)
			if err := c.VerifySigningPIN([]byte(f.pin)); err != nil {
				t.Fatal(err)
			}
			msg := bytes.Repeat([]byte("m"), MaxManifestSize)
			sig, err := c.Sign(msg)
			if err != nil || !ed25519.Verify(pub, msg, sig) {
				t.Fatal("signature over full manifest bytes does not verify", err)
			}
			if tc.extended && (f.extended == 0 || f.chained != 0) || !tc.extended && f.chained == 0 {
				t.Fatalf("extended=%d chained=%d", f.extended, f.chained)
			}
		})
	}
}

func TestWrongPINIsReported(t *testing.T) {
	f := newFakeCard(3070)
	c, err := NewCard(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyAdminPIN([]byte("wrong-pin")); !errors.Is(err, ErrWrongPIN) {
		t.Fatalf("got %v", err)
	}
	if f.adminTries != 2 {
		t.Fatal("fake did not count the try")
	}
}

func TestSignManifestChecksCardBeforePIN(t *testing.T) {
	f := newFakeCard(3070)
	_, pub := generated(t, f)
	f.adminOK = false
	defer func(o func(uint32) (*Card, error)) { openCard = o }(openCard)
	opens := 0
	openCard = func(serial uint32) (*Card, error) {
		opens++
		f.pinOK = false // every session starts unauthenticated
		return NewCard(f)
	}
	asked := 0
	pin := func() ([]byte, error) { asked++; return []byte(f.pin), nil }
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := SignManifest(1, other, []byte("{}\n"), pin, nil); err == nil || asked != 0 {
		t.Fatalf("wrong key: err=%v, PIN asked %d times", err, asked)
	}
	big := bytes.Repeat([]byte("x"), MaxManifestSize+1)
	if _, err := SignManifest(1, pub, big, pin, nil); err == nil || asked != 0 || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("oversize: err=%v, PIN asked %d times", err, asked)
	}
	touched := 0
	opens = 0
	msg := []byte("{\n  \"schema\": 1\n}\n")
	sig, err := SignManifest(1, pub, msg, pin, func() { touched++ })
	if err != nil || !ed25519.Verify(pub, msg, sig) || asked != 1 || touched != 1 {
		t.Fatalf("err=%v asked=%d touched=%d", err, asked, touched)
	}
	if opens != 2 {
		t.Fatalf("the PIN must be read between two short card sessions, got %d sessions", opens)
	}
}

func TestCheckSize(t *testing.T) {
	if CheckSize(MaxManifestSize) != nil || CheckSize(MaxManifestSize+1) == nil {
		t.Fatal("size bound")
	}
	if MaxManifestSize > 3070-256 {
		t.Fatal("keep a margin below the YubiKey 5 OpenPGP 3070-byte command limit")
	}
}

// RFC 9580, sample v4 Ed25519Legacy key.
func TestOpenPGPFingerprintVector(t *testing.T) {
	pub, _ := hex.DecodeString("3f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406")
	fp := OpenPGPFingerprint(pub, 0x53f35f0b)
	if hex.EncodeToString(fp[:]) != "c959bdbafa32a2f89a153b678cfde12197965a9a" {
		t.Fatalf("fingerprint %x", fp)
	}
}

func TestParseTLVRejectsTruncated(t *testing.T) {
	for _, b := range [][]byte{{0x6E}, {0x6E, 0x05, 0x01}, {0x7F}, {0x6E, 0x82, 0x01}, {0x6E, 0x83, 0, 0, 0}} {
		if _, err := parseTLV(b); err == nil {
			t.Fatalf("accepted %x", b)
		}
	}
}

func TestEncodeAPDU(t *testing.T) {
	if got := encodeAPDU(0, 0x2A, 0x9E, 0x9A, make([]byte, 300), 256, true); !bytes.Equal(got[:7], []byte{0, 0x2A, 0x9E, 0x9A, 0, 0x01, 0x2C}) || !bytes.Equal(got[len(got)-2:], []byte{0x01, 0x00}) || len(got) != 4+3+300+2 {
		t.Fatalf("extended %x", got[:8])
	}
	if got := encodeAPDU(0, 0xCA, 0, 0x6E, nil, 256, false); !bytes.Equal(got, []byte{0, 0xCA, 0, 0x6E, 0}) {
		t.Fatalf("short %x", got)
	}
}

// The vectors were produced by the production YubiKeys during the key
// ceremony and prove their output is plain Ed25519 over the exact bytes.
func TestHardwareKeyVectors(t *testing.T) {
	for _, v := range []struct{ key, id, dir string }{
		{"lRcnhdj4yU4TrinOa4U177FG7wrwUPv/v9zxA/WiJMI=", "e6fb20d55656904a", "yubikey-22337246"},
		{"6K8uY/1qIogN2j3ZdpEr4PuTqXzH7EseTd6kzHxpIr4=", "095d295f5fe9a4e2", "yubikey-19344964"},
	} {
		pub, err := base64.StdEncoding.Strict().DecodeString(v.key)
		if err != nil || KeyID(pub) != v.id {
			t.Fatalf("%s: key ID mismatch", v.dir)
		}
		msg, err := os.ReadFile(filepath.Join("testdata", v.dir, "manifest-2560.json"))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join("testdata", v.dir, "manifest-2560.json.sig"))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(string(raw), "\n"))
		if err != nil || len(msg) != MaxManifestSize || !ed25519.Verify(pub, msg, sig) {
			t.Fatalf("%s: hardware vector does not verify", v.dir)
		}
	}
}
