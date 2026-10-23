// SPDX-License-Identifier: MPL-2.0
// VLESS wire format adapted from Xray-core v1.260327.0.
// Modified for Bimeron's transport interfaces.
package vless

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func userID(id string) ([16]byte, error) {
	var b [16]byte
	decoded, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil || len(decoded) != 16 {
		return b, fmt.Errorf("invalid VLESS user ID")
	}
	copy(b[:], decoded)
	return b, nil
}

func addressBytes(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid VLESS destination")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || host == "" {
		return nil, fmt.Errorf("invalid VLESS destination")
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(port))
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() || ip.Is4In6() {
			b = append(b, 1)
			v4 := ip.Unmap().As4()
			return append(b, v4[:]...), nil
		}
		b = append(b, 3)
		v6 := ip.As16()
		return append(b, v6[:]...), nil
	}
	if len(host) > 255 || strings.ContainsAny(host, " /\t\r\n") {
		return nil, fmt.Errorf("invalid VLESS destination")
	}
	b = append(b, 2, byte(len(host)))
	return append(b, host...), nil
}

func requestHeader(id [16]byte, command byte, target, flow string) ([]byte, error) {
	address, err := addressBytes(target)
	if err != nil {
		return nil, err
	}
	if len(flow) > 253 {
		return nil, fmt.Errorf("invalid VLESS flow")
	}
	b := make([]byte, 0, 24+len(address)+len(flow))
	b = append(b, 0)
	b = append(b, id[:]...)
	if flow == "" {
		b = append(b, 0)
	} else {
		b = append(b, byte(len(flow)+2), 0x0a, byte(len(flow)))
		b = append(b, flow...)
	}
	b = append(b, command)
	if command == 3 {
		return b, nil
	}
	return append(b, address...), nil
}

func readResponseHeader(r io.Reader) error {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return fmt.Errorf("VLESS response unavailable: %w", err)
	}
	if b[0] != 0 {
		return fmt.Errorf("unsupported VLESS response version")
	}
	if b[1] > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(b[1])); err != nil {
			return fmt.Errorf("invalid VLESS response addons")
		}
	}
	return nil
}
