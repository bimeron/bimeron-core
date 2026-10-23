// SPDX-License-Identifier: MPL-2.0
// Client handshake adapted from Xray-core transport/internet/reality/reality.go
// (v1.260327.0). Modified for Bimeron's transport interfaces.
package vless

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"bimeron/internal/accesskey"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

func fingerprint(name string) (utls.ClientHelloID, error) {
	switch name {
	case "chrome":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unsupported REALITY fingerprint")
	}
}

func realityHandshake(ctx context.Context, raw net.Conn, settings accesskey.VLESS, publicKey, shortID []byte) (*utls.UConn, error) {
	helloID, err := fingerprint(settings.Fingerprint)
	if err != nil {
		return nil, err
	}
	var authKey []byte
	verified := false
	config := &utls.Config{ServerName: settings.ServerName, InsecureSkipVerify: true, SessionTicketsDisabled: true}
	config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("REALITY certificate missing")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return errors.New("invalid REALITY certificate")
		}
		key, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("REALITY authentication failed")
		}
		h := hmac.New(sha512.New, authKey)
		_, _ = h.Write(key)
		if !hmac.Equal(h.Sum(nil), cert.Signature) {
			return errors.New("REALITY authentication failed")
		}
		verified = true
		return nil
	}
	secure := utls.UClient(raw, config, helloID)
	if err := secure.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("REALITY client hello failed")
	}
	hello := secure.HandshakeState.Hello
	if len(hello.Raw) < 71 || len(hello.Random) != 32 {
		return nil, fmt.Errorf("invalid REALITY client hello")
	}
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	hello.SessionId[0], hello.SessionId[1], hello.SessionId[2] = 26, 3, 27
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], shortID)
	peer, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid REALITY public key")
	}
	ecdhe := secure.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		ecdhe = secure.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, fmt.Errorf("REALITY fingerprint lacks TLS 1.3 key share")
	}
	authKey, err = ecdhe.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("REALITY key agreement failed")
	}
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, fmt.Errorf("REALITY key derivation failed")
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, fmt.Errorf("REALITY cipher initialization failed")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("REALITY cipher initialization failed")
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("REALITY handshake failed: %w", err)
	}
	if !verified {
		return nil, fmt.Errorf("REALITY authentication failed")
	}
	return secure, nil
}
