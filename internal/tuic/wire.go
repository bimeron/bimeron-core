package tuic

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const version = 5

func addressBytes(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return nil, fmt.Errorf("invalid TUIC target")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid TUIC target port")
	}
	var out []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append([]byte{1}, v4...)
		} else {
			out = append([]byte{2}, ip.To16()...)
		}
	} else {
		if len(host) > 255 || len(host) == 0 {
			return nil, fmt.Errorf("invalid TUIC target name")
		}
		out = append([]byte{0, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(out, uint16(port)), nil
}

func readAddress(r io.Reader) (net.Addr, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return nil, err
	}
	var host string
	switch kind[0] {
	case 0xff:
		// Later fragments omit the address and port.
		return nil, nil
	case 0:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil || length[0] == 0 {
			return nil, fmt.Errorf("invalid TUIC address")
		}
		b := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		host = string(b)
	case 1, 2:
		length := 4
		if kind[0] == 2 {
			length = 16
		}
		b := make([]byte, length)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		host = net.IP(b).String()
	default:
		return nil, fmt.Errorf("invalid TUIC address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return nil, err
	}
	return packetAddr(net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:]))))), nil
}

type packetAddr string

func (a packetAddr) Network() string { return "udp" }
func (a packetAddr) String() string  { return string(a) }
