package anytls

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	cmdWaste byte = iota
	cmdSYN
	cmdPSH
	cmdFIN
	cmdSettings
	cmdAlert
	cmdUpdatePadding
	cmdSYNACK
	cmdHeartRequest
	cmdHeartResponse
	cmdServerSettings
)

func frame(command byte, id uint32, data []byte) []byte {
	b := make([]byte, 7+len(data))
	b[0] = command
	binary.BigEndian.PutUint32(b[1:5], id)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(data)))
	copy(b[7:], data)
	return b
}

func readFrame(r io.Reader) (byte, uint32, []byte, error) {
	var header [7]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, 0, nil, err
	}
	data := make([]byte, int(binary.BigEndian.Uint16(header[5:])))
	_, err := io.ReadFull(r, data)
	return header[0], binary.BigEndian.Uint32(header[1:5]), data, err
}

// socksAddress is the address format carried by an AnyTLS TCP stream.
func socksAddress(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid AnyTLS destination")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid AnyTLS destination port")
	}
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append([]byte{1}, v4...)
		} else {
			b = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid AnyTLS destination name")
		}
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

// UoT v2 uses address families 0, 1, and 2 instead of SOCKS5's 1, 4, and 3.
func uotAddress(addr net.Addr) ([]byte, error) {
	if addr == nil {
		return nil, fmt.Errorf("missing AnyTLS UDP destination")
	}
	b, err := socksAddress(addr.String())
	if err != nil {
		return nil, err
	}
	switch b[0] {
	case 1:
		b[0] = 0
	case 4:
		b[0] = 1
	case 3:
		b[0] = 2
	}
	return b, nil
}

func readUoTAddress(r io.Reader) (net.Addr, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return nil, err
	}
	var host string
	switch kind[0] {
	case 0:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, err
		}
		host = net.IP(ip[:]).String()
	case 1:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, err
		}
		host = net.IP(ip[:]).String()
	case 2:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil || size[0] == 0 {
			return nil, fmt.Errorf("invalid AnyTLS UDP address")
		}
		name := make([]byte, size[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return nil, err
		}
		host = string(name)
	default:
		return nil, fmt.Errorf("invalid AnyTLS UDP address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return nil, err
	}
	return packetAddress(net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:]))))), nil
}

type packetAddress string

func (a packetAddress) Network() string { return "udp" }
func (a packetAddress) String() string  { return string(a) }
