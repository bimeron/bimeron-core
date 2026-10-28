package ss2022

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type packetListener struct{ client *Client }

func (c *Client) PacketListener() *packetListener { return &packetListener{c} }

func (l *packetListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := l.client.dialer.DialContext(ctx, "udp", l.client.server)
	if err != nil {
		return nil, err
	}
	p := &packetConn{Conn: conn, client: l.client, sessions: make(map[[8]byte]*replayWindow)}
	if _, err = rand.Read(p.sessionID[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if l.client.method != "2022-blake3-chacha20-poly1305" {
		p.block, err = aes.NewCipher(l.client.key)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		p.sendAEAD, err = l.client.aead(p.sessionID[:])
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	} else {
		p.sendAEAD, err = chacha20poly1305.NewX(l.client.key)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return p, nil
}

type replayWindow struct {
	max  uint64
	seen map[uint64]struct{}
}

func (w *replayWindow) accept(id uint64) bool {
	if id < w.max && w.max-id > 1024 {
		return false
	}
	if _, exists := w.seen[id]; exists {
		return false
	}
	if id > w.max {
		w.max = id
	}
	w.seen[id] = struct{}{}
	for old := range w.seen {
		if old < w.max && w.max-old > 1024 {
			delete(w.seen, old)
		}
	}
	return true
}

type packetConn struct {
	net.Conn
	client          *Client
	block           cipher.Block
	sendAEAD        cipher.AEAD
	sessionID       [8]byte
	packetID        uint64
	sessions        map[[8]byte]*replayWindow
	readMu, writeMu sync.Mutex
}

func (p *packetConn) WriteTo(payload []byte, destination net.Addr) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	addr, err := address(destination.String())
	if err != nil {
		return 0, err
	}
	if p.packetID == ^uint64(0) {
		return 0, fmt.Errorf("Shadowsocks 2022 UDP packet counter exhausted")
	}
	body := make([]byte, 11, 11+len(addr)+len(payload))
	binary.BigEndian.PutUint64(body[1:], uint64(time.Now().Unix()))
	body = append(body, addr...)
	body = append(body, payload...)
	var packet []byte
	if p.block != nil {
		header := make([]byte, 16)
		copy(header, p.sessionID[:])
		binary.BigEndian.PutUint64(header[8:], p.packetID)
		var nonce [12]byte
		copy(nonce[:], header[4:])
		packet = make([]byte, 16)
		p.block.Encrypt(packet, header)
		packet = p.sendAEAD.Seal(packet, nonce[:], body, nil)
	} else {
		packet = make([]byte, chacha20poly1305.NonceSizeX)
		if _, err = rand.Read(packet); err != nil {
			return 0, err
		}
		plain := make([]byte, 16, 16+len(body))
		copy(plain, p.sessionID[:])
		binary.BigEndian.PutUint64(plain[8:], p.packetID)
		plain = append(plain, body...)
		packet = p.sendAEAD.Seal(packet, packet, plain, nil)
	}
	if len(packet) > 65507 {
		return 0, fmt.Errorf("Shadowsocks 2022 UDP packet too large")
	}
	if _, err = p.Conn.Write(packet); err != nil {
		return 0, err
	}
	p.packetID++
	return len(payload), nil
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	packet := make([]byte, 65535)
	for {
		n, err := p.Conn.Read(packet)
		if err != nil {
			return 0, nil, err
		}
		var header, body []byte
		if p.block != nil {
			if n < 16+16 {
				continue
			}
			header = make([]byte, 16)
			p.block.Decrypt(header, packet[:16])
			var nonce [12]byte
			copy(nonce[:], header[4:])
			aead, err := p.client.aead(header[:8])
			if err != nil {
				continue
			}
			body, err = aead.Open(nil, nonce[:], packet[16:n], nil)
			if err != nil {
				continue
			}
		} else {
			if n < chacha20poly1305.NonceSizeX+16+16 {
				continue
			}
			plain, err := p.sendAEAD.Open(nil, packet[:chacha20poly1305.NonceSizeX], packet[chacha20poly1305.NonceSizeX:n], nil)
			if err != nil {
				continue
			}
			header, body = plain[:16], plain[16:]
		}
		if len(body) < 1+8+8+2 || body[0] != 1 || !validTime(body[1:9]) || subtle.ConstantTimeCompare(body[9:17], p.sessionID[:]) != 1 {
			continue
		}
		pad := int(binary.BigEndian.Uint16(body[17:19]))
		if len(body) < 19+pad {
			continue
		}
		source, used, err := parseAddress(body[19+pad:])
		if err != nil {
			continue
		}
		payload := body[19+pad+used:]
		if len(payload) > len(b) {
			return 0, nil, fmt.Errorf("Shadowsocks 2022 UDP receive buffer too small")
		}
		var sid [8]byte
		copy(sid[:], header[:8])
		window := p.sessions[sid]
		if window == nil {
			if len(p.sessions) >= 32 {
				continue
			}
			window = &replayWindow{seen: make(map[uint64]struct{})}
			p.sessions[sid] = window
		}
		if !window.accept(binary.BigEndian.Uint64(header[8:])) {
			continue
		}
		return copy(b, payload), source, nil
	}
}
