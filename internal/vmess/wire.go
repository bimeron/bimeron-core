// SPDX-License-Identifier: MPL-2.0
// Adapted from Xray-core v1.260327.0 proxy/vmess/aead and proxy/vmess/encoding.
// See third_party/vmess/README.md for attribution.
package vmess

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

type nestedHash struct{ hash.Hash }

func kdf(key []byte, path ...string) []byte {
	h := hmac.New(sha256.New, []byte("VMess AEAD KDF"))
	for _, p := range path {
		first := true
		previous := h
		h = hmac.New(func() hash.Hash {
			if first {
				first = false
				return nestedHash{previous}
			}
			return previous
		}, []byte(p))
	}
	h.Write(key)
	return h.Sum(nil)
}

func kdf16(key []byte, path ...string) []byte { return kdf(key, path...)[:16] }

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func sealHeader(cmdKey [16]byte, plain []byte) ([]byte, error) {
	var auth [16]byte
	binary.BigEndian.PutUint64(auth[:8], uint64(time.Now().Unix()))
	if _, err := rand.Read(auth[8:12]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(auth[12:], crc32.ChecksumIEEE(auth[:12]))
	block, err := aes.NewCipher(kdf16(cmdKey[:], "AES Auth ID Encryption"))
	if err != nil {
		return nil, err
	}
	block.Encrypt(auth[:], auth[:])
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	lengthAEAD, err := gcm(kdf16(cmdKey[:], "VMess Header AEAD Key_Length", string(auth[:]), string(nonce[:])))
	if err != nil {
		return nil, err
	}
	dataAEAD, err := gcm(kdf16(cmdKey[:], "VMess Header AEAD Key", string(auth[:]), string(nonce[:])))
	if err != nil {
		return nil, err
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(plain)))
	out := append([]byte(nil), auth[:]...)
	out = lengthAEAD.Seal(out, kdf(cmdKey[:], "VMess Header AEAD Nonce_Length", string(auth[:]), string(nonce[:]))[:12], length[:], auth[:])
	out = append(out, nonce[:]...)
	out = dataAEAD.Seal(out, kdf(cmdKey[:], "VMess Header AEAD Nonce", string(auth[:]), string(nonce[:]))[:12], plain, auth[:])
	return out, nil
}

func requestHeader(id [16]byte, command byte, target string, security byte) ([]byte, [16]byte, [16]byte, byte, error) {
	var iv, key [16]byte
	var response [1]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return nil, iv, key, 0, err
	}
	if _, err := rand.Read(key[:]); err != nil {
		return nil, iv, key, 0, err
	}
	if _, err := rand.Read(response[:]); err != nil {
		return nil, iv, key, 0, err
	}
	address, err := encodeAddress(target)
	if err != nil {
		return nil, iv, key, 0, err
	}
	var pad [1]byte
	if _, err := rand.Read(pad[:]); err != nil {
		return nil, iv, key, 0, err
	}
	padLen := int(pad[0] % 16)
	plain := []byte{1}
	plain = append(plain, iv[:]...)
	plain = append(plain, key[:]...)
	plain = append(plain, response[0], 0x0d, byte(padLen<<4)|security, 0, command)
	plain = append(plain, address...)
	padding := make([]byte, padLen)
	if _, err := rand.Read(padding); err != nil {
		return nil, iv, key, 0, err
	}
	plain = append(plain, padding...)
	sum := fnv.New32a()
	sum.Write(plain)
	plain = binary.BigEndian.AppendUint32(plain, sum.Sum32())
	h := md5.New()
	h.Write(id[:])
	h.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	var cmdKey [16]byte
	copy(cmdKey[:], h.Sum(nil))
	header, err := sealHeader(cmdKey, plain)
	return header, iv, key, response[0], err
}

func encodeAddress(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return nil, fmt.Errorf("invalid VMess destination")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid VMess destination")
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(port))
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() || ip.Is4In6() {
			a := ip.Unmap().As4()
			return append(append(b, 1), a[:]...), nil
		}
		a := ip.As16()
		return append(append(b, 3), a[:]...), nil
	}
	if len(host) > 255 || strings.ContainsAny(host, " /\t\r\n") {
		return nil, fmt.Errorf("invalid VMess destination")
	}
	return append(append(b, 2, byte(len(host))), host...), nil
}

type chunkCodec struct {
	aead  cipher.AEAD
	iv    [16]byte
	count uint32
	shake sha3.ShakeHash
	conn  net.Conn
	done  bool
}

func newChunkCodec(conn net.Conn, key, iv [16]byte, security string) (*chunkCodec, error) {
	var aead cipher.AEAD
	var err error
	if security == "chacha20-poly1305" {
		first := md5.Sum(key[:])
		second := md5.Sum(first[:])
		material := append(first[:], second[:]...)
		aead, err = chacha20poly1305.New(material)
	} else {
		aead, err = gcm(key[:])
	}
	if err != nil {
		return nil, err
	}
	shake := sha3.NewShake128()
	shake.Write(iv[:])
	return &chunkCodec{aead: aead, iv: iv, shake: shake, conn: conn}, nil
}

func (c *chunkCodec) nextPadding() uint16 {
	var b [2]byte
	c.shake.Read(b[:])
	return binary.BigEndian.Uint16(b[:]) % 64
}

func (c *chunkCodec) mask(size uint16) [2]byte {
	var b [2]byte
	c.shake.Read(b[:])
	binary.BigEndian.PutUint16(b[:], binary.BigEndian.Uint16(b[:])^size)
	return b
}

func (c *chunkCodec) nonce() ([]byte, error) {
	if c.count > 65535 {
		return nil, fmt.Errorf("VMess chunk limit reached")
	}
	var nonce [12]byte
	copy(nonce[:], c.iv[:12])
	binary.BigEndian.PutUint16(nonce[:2], uint16(c.count))
	c.count++
	return nonce[:], nil
}

func (c *chunkCodec) writeFrame(b []byte) error {
	if len(b) > 8192-82 {
		return fmt.Errorf("VMess chunk too large")
	}
	padding := c.nextPadding()
	size := uint16(len(b)+c.aead.Overhead()) + padding
	length := c.mask(size)
	nonce, err := c.nonce()
	if err != nil {
		return err
	}
	frame := c.aead.Seal(length[:], nonce, b, nil)
	if padding > 0 {
		p := make([]byte, padding)
		if _, err := rand.Read(p); err != nil {
			return err
		}
		frame = append(frame, p...)
	}
	return writeAll(c.conn, frame)
}

func (c *chunkCodec) readFrame() ([]byte, error) {
	if c.done {
		return nil, io.EOF
	}
	var length [2]byte
	if _, err := io.ReadFull(c.conn, length[:]); err != nil {
		return nil, err
	}
	padding := c.nextPadding()
	var mask [2]byte
	c.shake.Read(mask[:])
	size := binary.BigEndian.Uint16(length[:]) ^ binary.BigEndian.Uint16(mask[:])
	if size < uint16(c.aead.Overhead())+padding || size > 8192 {
		return nil, fmt.Errorf("invalid VMess chunk size")
	}
	frame := make([]byte, size)
	if _, err := io.ReadFull(c.conn, frame); err != nil {
		return nil, err
	}
	nonce, err := c.nonce()
	if err != nil {
		return nil, err
	}
	plain, err := c.aead.Open(nil, nonce, frame[:int(size-padding)], nil)
	if err != nil {
		return nil, fmt.Errorf("invalid VMess chunk")
	}
	if len(plain) == 0 {
		c.done = true
		return nil, io.EOF
	}
	return plain, nil
}

func readResponseHeader(conn net.Conn, key, iv [16]byte, expected byte) error {
	responseKey := sha256.Sum256(key[:])
	responseIV := sha256.Sum256(iv[:])
	lengthAEAD, err := gcm(kdf16(responseKey[:16], "AEAD Resp Header Len Key"))
	if err != nil {
		return err
	}
	var sealedLength [18]byte
	if _, err = io.ReadFull(conn, sealedLength[:]); err != nil {
		return err
	}
	length, err := lengthAEAD.Open(nil, kdf(responseIV[:16], "AEAD Resp Header Len IV")[:12], sealedLength[:], nil)
	if err != nil || len(length) != 2 {
		return fmt.Errorf("invalid VMess response length")
	}
	n := int(binary.BigEndian.Uint16(length))
	if n < 4 || n > 4096 {
		return fmt.Errorf("invalid VMess response header")
	}
	sealed := make([]byte, n+16)
	if _, err = io.ReadFull(conn, sealed); err != nil {
		return err
	}
	headerAEAD, err := gcm(kdf16(responseKey[:16], "AEAD Resp Header Key"))
	if err != nil {
		return err
	}
	header, err := headerAEAD.Open(nil, kdf(responseIV[:16], "AEAD Resp Header IV")[:12], sealed, nil)
	if err != nil || len(header) < 4 || header[0] != expected || header[2] != 0 {
		return fmt.Errorf("invalid VMess response header")
	}
	return nil
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
