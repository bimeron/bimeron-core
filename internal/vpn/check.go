package vpn

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

// CheckTCP verifies the upstream without changing system routes.
func CheckTCP(ctx context.Context, tcp transport.StreamDialer) (string, error) {
	httpTransport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return tcp.DialStream(ctx, address)
	}}
	defer httpTransport.CloseIdleConnections()
	client := &http.Client{Transport: httpTransport, Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("TCP/TLS check failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("TCP check endpoint returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65))
	if err != nil || net.ParseIP(strings.TrimSpace(string(b))) == nil {
		return "", fmt.Errorf("TCP check did not return an IP address")
	}
	return strings.TrimSpace(string(b)), nil
}

// Check tests real TCP/TLS and UDP/DNS before system routes are captured.
func Check(ctx context.Context, tcp transport.StreamDialer, udp transport.PacketListener, dns []string) (string, error) {
	address, err := CheckTCP(ctx, tcp)
	if err != nil {
		return "", err
	}
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	id := binary.BigEndian.Uint16(random[:])
	name, _ := dnsmessage.NewName("api.ipify.org.")
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	packet, err := message.Pack()
	if err != nil {
		return "", err
	}
	answer, err := (DNSResolver{Servers: dns, TCP: tcp, UDP: udp}).Exchange(ctx, packet, false)
	if err != nil {
		return "", fmt.Errorf("UDP/DNS check failed for all configured resolvers")
	}
	var response dnsmessage.Message
	if err := response.Unpack(answer); err != nil {
		return "", fmt.Errorf("invalid DNS check answer")
	}
	if response.Truncated {
		answer, err = (DNSResolver{Servers: dns, TCP: tcp, UDP: udp}).Exchange(ctx, packet, true)
		if err != nil || response.Unpack(answer) != nil {
			return "", fmt.Errorf("DNS TCP fallback failed")
		}
	}
	if response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) == 0 {
		return "", fmt.Errorf("DNS resolver returned no usable answer")
	}
	return address, nil
}
