// SPDX-License-Identifier: MPL-2.0
// Vision framing adapted from Xray-core proxy/proxy.go v1.260327.0.
// Modified for Bimeron's transport interfaces.
// The direct-copy transition relies on the pinned uTLS Conn buffer layout.
package vless

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"reflect"
	"sync"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
)

const maxVisionBlock = 8192 // Xray's common/buf.Size at the pinned protocol version.

type visionConn struct {
	secure                             *utls.UConn
	raw                                net.Conn
	id                                 [16]byte
	readMu, writeMu                    sync.Mutex
	stateMu                            sync.Mutex
	filterLeft                         int
	isTLS, isTLS13                     bool
	serverHelloLeft                    int
	cipher                             uint16
	firstWrite                         bool
	writePadding, directWrite          bool
	firstRead, readPadding, directRead bool
	readCommand                        byte
	contentLeft, paddingLeft           int
	readBuf                            []byte
	pending                            []byte
	inFrame                            bool
	ready                              bool
	decodeErr                          error
}

func newVisionConn(secure *utls.UConn, raw net.Conn, id [16]byte) (*visionConn, error) {
	t := reflect.TypeOf(secure.Conn).Elem()
	if input, ok := t.FieldByName("input"); !ok || input.Type != reflect.TypeFor[bytes.Reader]() {
		return nil, errors.New("unsupported uTLS read buffer layout")
	}
	if rawInput, ok := t.FieldByName("rawInput"); !ok || rawInput.Type != reflect.TypeFor[bytes.Buffer]() {
		return nil, errors.New("unsupported uTLS raw buffer layout")
	}
	return &visionConn{secure: secure, raw: raw, id: id, filterLeft: 8, firstWrite: true, writePadding: true, firstRead: true, readPadding: true}, nil
}

func (v *visionConn) filterTLS(b []byte) {
	v.stateMu.Lock()
	defer v.stateMu.Unlock()
	if v.filterLeft <= 0 {
		return
	}
	v.filterLeft--
	if len(b) >= 6 {
		if bytes.Equal(b[:3], []byte{0x16, 3, 3}) && b[5] == 2 {
			v.serverHelloLeft = int(binary.BigEndian.Uint16(b[3:5])) + 5
			v.isTLS = true
			if len(b) >= 79 {
				i := 43 + int(b[43]) + 1
				if i+2 <= len(b) {
					v.cipher = binary.BigEndian.Uint16(b[i:])
				}
			}
		} else if b[0] == 0x16 && b[1] == 3 && b[5] == 1 {
			v.isTLS = true
		}
	}
	if v.serverHelloLeft > 0 {
		end := min(v.serverHelloLeft, len(b))
		v.serverHelloLeft -= len(b)
		if bytes.Contains(b[:end], []byte{0, 0x2b, 0, 2, 3, 4}) {
			v.isTLS13 = v.cipher >= 0x1301 && v.cipher <= 0x1304
			v.filterLeft = 0
		} else if v.serverHelloLeft <= 0 {
			v.filterLeft = 0
		}
	}
}

func randomPadding(content int, long bool) (int, error) {
	limit, base := int64(256), 0
	if long && content < 900 {
		limit, base = 500, 900-content
	}
	n, err := rand.Int(rand.Reader, big.NewInt(limit))
	if err != nil {
		return 0, err
	}
	return min(base+int(n.Int64()), maxVisionBlock-21-content), nil
}

func (v *visionConn) paddingBlock(content []byte, command byte, long bool) ([]byte, error) {
	padding, err := randomPadding(len(content), long)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, 21+len(content)+padding)
	if v.firstWrite {
		b = append(b, v.id[:]...)
		v.firstWrite = false
	}
	b = append(b, command, byte(len(content)>>8), byte(len(content)), byte(padding>>8), byte(padding))
	b = append(b, content...)
	b = append(b, make([]byte, padding)...)
	return b, nil
}

func (v *visionConn) start(header []byte) error {
	v.writeMu.Lock()
	defer v.writeMu.Unlock()
	block, err := v.paddingBlock(nil, 0, true)
	if err != nil {
		return err
	}
	request := append(header, block...)
	n, err := v.secure.Write(request)
	if err == nil && n != len(request) {
		err = io.ErrShortWrite
	}
	return err
}

func completeTLSRecords(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for len(b) > 0 {
		if len(b) < 5 || b[0] != 0x17 || b[1] != 3 || b[2] != 3 {
			return false
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if n == 0 || n+5 > len(b) {
			return false
		}
		b = b[n+5:]
	}
	return true
}

func (v *visionConn) Write(b []byte) (int, error) {
	v.writeMu.Lock()
	defer v.writeMu.Unlock()
	total := 0
	for len(b) > 0 {
		if v.directWrite {
			n, err := v.raw.Write(b)
			if err == nil && n != len(b) {
				err = io.ErrShortWrite
			}
			return total + n, err
		}
		chunk := b[:min(len(b), maxVisionBlock-21)]
		v.filterTLS(chunk)
		v.stateMu.Lock()
		isTLS, isTLS13, filterLeft := v.isTLS, v.isTLS13, v.filterLeft
		v.stateMu.Unlock()
		data := chunk
		command := byte(0)
		if v.writePadding {
			if isTLS && len(chunk) >= 6 && bytes.Equal(chunk[:3], []byte{0x17, 3, 3}) && completeTLSRecords(chunk) {
				command = 1
				if isTLS13 {
					command = 2
				}
				v.writePadding = false
			} else if !isTLS && filterLeft <= 0 {
				command = 1
				v.writePadding = false
			}
			var err error
			data, err = v.paddingBlock(chunk, command, isTLS)
			if err != nil {
				return total, err
			}
		}
		if n, err := v.secure.Write(data); err != nil {
			return total, err
		} else if n != len(data) {
			return total, io.ErrShortWrite
		}
		if command == 2 {
			v.directWrite = true
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
}

func (v *visionConn) bufferedRaw() []byte {
	t := reflect.TypeOf(v.secure.Conn).Elem()
	base := unsafe.Pointer(v.secure.Conn)
	inputField, _ := t.FieldByName("input")
	rawField, _ := t.FieldByName("rawInput")
	input := (*bytes.Reader)(unsafe.Add(base, inputField.Offset))
	rawInput := (*bytes.Buffer)(unsafe.Add(base, rawField.Offset))
	b, _ := io.ReadAll(input)
	b = append(b, rawInput.Bytes()...)
	*input = bytes.Reader{}
	*rawInput = bytes.Buffer{}
	return b
}

func (v *visionConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	v.readMu.Lock()
	defer v.readMu.Unlock()
	if !v.ready {
		if err := readResponseHeader(v.secure); err != nil {
			return 0, err
		}
		v.ready = true
	}
	for {
		if len(v.readBuf) > 0 {
			n := copy(b, v.readBuf)
			v.readBuf = v.readBuf[n:]
			return n, nil
		}
		if v.directRead {
			return v.raw.Read(b)
		}
		var block [maxVisionBlock]byte
		n, err := v.secure.Read(block[:])
		if n > 0 {
			v.decode(block[:n])
			if v.decodeErr != nil {
				return 0, v.decodeErr
			}
			if v.directRead {
				v.readBuf = append(v.readBuf, v.bufferedRaw()...)
			}
		}
		if len(v.readBuf) > 0 {
			continue
		}
		if err != nil {
			return 0, err
		}
	}
}

func (v *visionConn) decode(b []byte) {
	if !v.readPadding {
		v.readBuf = append(v.readBuf, b...)
		return
	}
	v.pending = append(v.pending, b...)
	// The first Vision block carries the user ID before its five-byte header.
	if v.firstRead {
		if len(v.pending) < 21 {
			return
		}
		if !bytes.Equal(v.pending[:16], v.id[:]) {
			v.readPadding = false
			v.firstRead = false
			v.readBuf = append(v.readBuf, v.pending...)
			v.pending = nil
			return
		}
		v.pending = v.pending[16:]
		v.firstRead = false
	}
	for len(v.pending) > 0 {
		if !v.inFrame {
			if len(v.pending) < 5 {
				return
			}
			v.readCommand = v.pending[0]
			v.contentLeft = int(binary.BigEndian.Uint16(v.pending[1:3]))
			v.paddingLeft = int(binary.BigEndian.Uint16(v.pending[3:5]))
			if v.readCommand > 2 || v.contentLeft+v.paddingLeft > maxVisionBlock-5 {
				v.decodeErr = errors.New("invalid Vision frame")
				return
			}
			v.pending = v.pending[5:]
			v.inFrame = true
		}
		content := min(v.contentLeft, len(v.pending))
		if content > 0 {
			v.readBuf = append(v.readBuf, v.pending[:content]...)
			v.filterTLS(v.pending[:content])
			v.contentLeft -= content
			v.pending = v.pending[content:]
		}
		padding := min(v.paddingLeft, len(v.pending))
		v.paddingLeft -= padding
		v.pending = v.pending[padding:]
		if v.contentLeft == 0 && v.paddingLeft == 0 {
			v.inFrame = false
			if v.readCommand != 0 {
				v.readPadding = false
				v.directRead = v.readCommand == 2
				v.readBuf = append(v.readBuf, v.pending...)
				v.pending = nil
				return
			}
		}
		if content == 0 && padding == 0 && v.inFrame {
			return
		}
	}
}

func (v *visionConn) Close() error { return v.raw.Close() }
func (v *visionConn) CloseRead() error {
	if c, ok := v.raw.(interface{ CloseRead() error }); ok {
		return c.CloseRead()
	}
	return v.raw.Close()
}
func (v *visionConn) CloseWrite() error {
	if c, ok := v.raw.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return v.raw.Close()
}
func (v *visionConn) LocalAddr() net.Addr                { return v.raw.LocalAddr() }
func (v *visionConn) RemoteAddr() net.Addr               { return v.raw.RemoteAddr() }
func (v *visionConn) SetDeadline(t time.Time) error      { return v.raw.SetDeadline(t) }
func (v *visionConn) SetReadDeadline(t time.Time) error  { return v.raw.SetReadDeadline(t) }
func (v *visionConn) SetWriteDeadline(t time.Time) error { return v.raw.SetWriteDeadline(t) }
