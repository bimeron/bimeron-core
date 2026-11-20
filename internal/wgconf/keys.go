package wgconf

import (
	"crypto/rand"
	"encoding/base64"

	"bimeron/internal/problem"
	"golang.org/x/crypto/curve25519"
)

// KeyOperations lists the key operations of the "bimeron wireguard" bridge.
var KeyOperations = []string{"generate_keypair", "public_key", "generate_preshared_key"}

// GenerateKeyPair returns a new Curve25519 key pair in base64. The private
// key is clamped as WireGuard tools do. Both values are secrets to callers.
func GenerateKeyPair() (private, public string, err error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return "", "", err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(pub), nil
}

// PublicKey derives the public key of a base64 private key. Problems never
// contain the input.
func PublicKey(private string) (string, error) {
	k, err := parseKey(private)
	if err == nil && k.IsZero() {
		err = errZeroKey()
	}
	if err != nil {
		return "", problem.Of(err).At("PrivateKey").InDocument(DocumentName)
	}
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		// Low-order results are rejected by X25519; report the key as invalid.
		return "", problem.New("wireguard_key_invalid", "WireGuard keys must be 32 bytes in base64").At("PrivateKey").InDocument(DocumentName)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// GeneratePresharedKey returns 32 random bytes in base64.
func GeneratePresharedKey() (string, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), nil
}
