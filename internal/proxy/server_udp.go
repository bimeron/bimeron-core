package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"bimeron/internal/routing"
)

// serveUDP is opt-in through Server.Packet. Each association is owned by its
// TCP control connection and accepts datagrams only from that loopback peer.
func (s *Server) serveUDP(ctx context.Context, control net.Conn, host string, port int) {
	peer := control.RemoteAddr().(*net.TCPAddr)
	requested := net.ParseIP(host)
	if requested == nil || (!requested.IsUnspecified() && !requested.Equal(peer.IP)) {
		_ = reply(control, 2)
		return
	}
	local := control.LocalAddr().(*net.TCPAddr)
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		_ = reply(control, 1)
		return
	}
	defer relay.Close()
	owned, cancel := context.WithCancel(ctx)
	defer cancel()
	upstream, err := s.Packet.ListenPacket(owned)
	if err != nil {
		_ = reply(control, 1)
		return
	}
	defer upstream.Close()
	direct, err := net.ListenPacket("udp", ":0")
	if err != nil {
		_ = reply(control, 1)
		return
	}
	defer direct.Close()
	var wg sync.WaitGroup
	stop := context.AfterFunc(owned, func() { _ = relay.Close(); _ = upstream.Close(); _ = direct.Close(); _ = control.Close() })
	defer func() {
		cancel()
		_ = relay.Close()
		_ = upstream.Close()
		_ = direct.Close()
		_ = control.Close()
		stop()
		wg.Wait()
	}()
	encoded, err := socksAddress(relay.LocalAddr().String())
	if err != nil {
		return
	}
	if _, err = control.Write(append([]byte{5, 0, 0}, encoded...)); err != nil {
		return
	}
	_ = control.SetDeadline(time.Time{})
	s.Stats.AttemptUDP()
	s.Stats.EstablishUDP()
	defer s.Stats.EndUDP()
	var mu sync.Mutex
	var source *net.UDPAddr
	allowed := make(map[string]routing.Action)
	forward := func(conn net.PacketConn, action routing.Action) {
		defer wg.Done()
		defer cancel()
		b := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFrom(b)
			if err != nil {
				var transient net.Error
				if owned.Err() == nil && errors.As(err, &transient) && transient.Temporary() {
					s.Stats.FailUDP()
					continue
				}
				return
			}
			mu.Lock()
			dest := source
			route, ok := allowed[from.String()]
			mu.Unlock()
			if dest == nil || !ok || route != action {
				continue
			}
			address, err := socksAddress(from.String())
			if err != nil {
				continue
			}
			packet := append([]byte{0, 0, 0}, address...)
			packet = append(packet, b[:n]...)
			if _, err := relay.WriteToUDP(packet, dest); err != nil {
				return
			}
			s.Stats.Received(int64(n))
		}
	}
	wg.Add(3)
	go forward(upstream, routing.Proxy)
	go forward(direct, routing.Direct)
	go func() { defer wg.Done(); defer cancel(); _, _ = io.Copy(io.Discard, control) }()
	b := make([]byte, 65535)
	for {
		_ = relay.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, from, err := relay.ReadFromUDP(b)
		if err != nil {
			return
		}
		if !from.IP.Equal(peer.IP) || (port != 0 && from.Port != port) || n < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
			continue
		}
		mu.Lock()
		known := source
		mu.Unlock()
		if known != nil && !known.IP.Equal(from.IP) {
			continue
		}
		if known != nil && known.Port != from.Port {
			continue
		}
		r := bytes.NewReader(b[4:n])
		target, err := readSocksAddress(r, b[3])
		if err != nil {
			continue
		}
		targetHost, portText, err := net.SplitHostPort(target)
		targetPort, portErr := strconv.Atoi(portText)
		if err != nil || portErr != nil || targetPort < 1 || targetHost == "" || strings.ContainsAny(targetHost, " /\r\n\t") {
			continue
		}
		ip, _ := netip.ParseAddr(targetHost)
		domain := ""
		if !ip.IsValid() {
			domain = targetHost
		}
		action := routing.Proxy
		if s.Policy != nil {
			action = s.Policy.Decide(ip, domain)
		}
		s.Stats.RouteDecided(action)
		if action == routing.Block {
			continue
		}
		var destination net.Addr = udpTarget(target)
		if action == routing.Direct {
			address := &net.UDPAddr{IP: net.ParseIP(targetHost), Port: targetPort}
			if address.IP == nil {
				lookup, cancelLookup := context.WithTimeout(owned, 15*time.Second)
				ips, err := net.DefaultResolver.LookupNetIP(lookup, "ip", targetHost)
				cancelLookup()
				if err != nil || len(ips) == 0 {
					continue
				}
				address.IP = net.IP(ips[0].AsSlice())
			}
			destination = address
		}
		mu.Lock()
		if _, ok := allowed[destination.String()]; !ok && len(allowed) >= 64 {
			mu.Unlock()
			continue
		}
		source = from
		allowed[destination.String()] = action
		mu.Unlock()
		payload := b[n-r.Len() : n]
		writer := upstream
		if action == routing.Direct {
			writer = direct
		}
		_ = writer.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if _, err := writer.WriteTo(payload, destination); err != nil {
			s.Stats.FailUDP()
			continue
		}
		s.Stats.Sent(int64(len(payload)))
	}
}

type udpTarget string

func (a udpTarget) Network() string { return "udp" }
func (a udpTarget) String() string  { return string(a) }
