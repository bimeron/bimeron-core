package proxy

import (
	"fmt"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	"net"
	"bimeron/internal/accesskey"
	"strconv"
	"unicode/utf8"
)

// OutlineUDP preserves separate UDP endpoints in tcpudp configurations.
func OutlineUDP(e accesskey.Endpoint, dialer net.Dialer) (transport.PacketListener, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	key, err := shadowsocks.NewEncryptionKey(e.Cipher, e.Secret)
	if err != nil {
		return nil, fmt.Errorf("could not create encryption key")
	}
	listener, err := shadowsocks.NewPacketListener(transport.UDPEndpoint{Address: net.JoinHostPort(e.Host, strconv.Itoa(e.Port)), Dialer: dialer}, key)
	if err != nil {
		return nil, err
	}
	if !utf8.ValidString(e.Prefix) {
		return nil, fmt.Errorf("invalid prefix encoding")
	}
	var prefix []byte
	for _, r := range e.Prefix {
		if r > 255 {
			return nil, fmt.Errorf("prefix must contain byte-valued characters")
		}
		prefix = append(prefix, byte(r))
	}
	if len(prefix) > key.SaltSize()-16 {
		return nil, fmt.Errorf("prefix too long for selected cipher")
	}
	if len(prefix) > 0 {
		listener.SetSaltGenerator(shadowsocks.NewPrefixSaltGenerator(prefix))
	}
	return listener, nil
}
