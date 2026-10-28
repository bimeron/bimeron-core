// This fixture runs the pinned, unmodified masque-go proxy on quic-go v0.63.0.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/dns/dnsmessage"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	must(err)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}
	endpoints := map[string]string{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	endpoints["tcp"] = tcp.Addr().String()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	for _, name := range []string{"udp", "udp2", "dns", "udp6"} {
		address := "127.0.0.1:0"
		if name == "udp6" {
			address = "[::1]:0"
		}
		socket, err := net.ListenPacket("udp", address)
		if name == "udp6" && err != nil {
			continue
		}
		must(err)
		endpoints[name] = socket.LocalAddr().String()
		go func() {
			b := make([]byte, 65535)
			for {
				n, from, err := socket.ReadFrom(b)
				if err != nil {
					return
				}
				data := b[:n]
				if name == "dns" {
					var message dnsmessage.Message
					if message.Unpack(data) != nil || len(message.Questions) == 0 {
						continue
					}
					message.Response, message.RecursionAvailable = true, true
					message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}}
					data, err = message.Pack()
					if err != nil {
						continue
					}
				}
				_, _ = socket.WriteTo(data, from)
			}
		}()
	}
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	must(err)
	endpoints["http3"] = target.LocalAddr().String()
	targetServer := &http3.Server{TLSConfig: tlsConfig, QUICConfig: &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "http3-through-masque") })}
	go targetServer.Serve(target)
	allowed := func(target string) bool {
		for _, name := range []string{"tcp", "udp", "udp2", "dns", "udp6", "http3"} {
			if endpoints[name] != "" && endpoints[name] == target {
				return true
			}
		}
		host, port, err := net.SplitHostPort(target)
		if err == nil && host == "localhost" {
			for _, name := range []string{"tcp", "udp", "udp2", "dns", "http3"} {
				_, p, _ := net.SplitHostPort(endpoints[name])
				if p == port {
					return true
				}
			}
		}
		return false
	}
	for _, name := range []string{"server", "no_datagrams"} {
		socket, err := net.ListenPacket("udp", "127.0.0.1:0")
		must(err)
		endpoints[name] = socket.LocalAddr().String()
		proxy := &masque.Proxy{}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("user:fixture-pass")) {
				w.WriteHeader(407)
				return
			}
			if r.Method != http.MethodConnect {
				w.WriteHeader(405)
				return
			}
			if r.Proto != "connect-udp" {
				if !allowed(r.Host) {
					w.WriteHeader(403)
					return
				}
				c, err := net.DialTimeout("tcp", r.Host, time.Second)
				if err != nil {
					w.WriteHeader(502)
					return
				}
				defer c.Close()
				w.WriteHeader(200)
				stream := w.(http3.HTTPStreamer).HTTPStream()
				defer stream.CancelRead(0)
				done := make(chan struct{})
				go func() { defer close(done); _, _ = io.Copy(c, stream); _ = c.(*net.TCPConn).CloseWrite() }()
				_, _ = io.Copy(stream, c)
				_ = stream.Close()
				_ = c.Close()
				stream.CancelRead(0)
				<-done
				return
			}
			prefix := "/.well-known/masque/udp/"
			for _, p := range []string{"/custom/", "/reject/", "/stall/", "/bad_capsule/", "/inject/", "/malformed_capsule/", "/oversized_header/"} {
				if strings.HasPrefix(r.URL.Path, p) {
					prefix = p
					break
				}
			}
			template := uritemplate.MustNew("https://" + r.Host + prefix + "{target_host}/{target_port}/")
			req, err := masque.ParseProxyRequest(r, template)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			if !allowed(req.Target) {
				w.WriteHeader(403)
				return
			}
			switch prefix {
			case "/reject/":
				w.WriteHeader(403)
				return
			case "/stall/":
				// Wait for a client stream reset; r.Context is not tied to a hijacked stream.
				_, _ = io.Copy(io.Discard, r.Body)
				return
			case "/oversized_header/":
				w.Header().Set("X-Large", strings.Repeat("x", 20*1024))
				w.WriteHeader(200)
				return
			case "/malformed_capsule/":
				w.Header().Set(http3.CapsuleProtocolHeader, "?1")
				w.WriteHeader(200)
				stream := w.(http3.HTTPStreamer).HTTPStream()
				defer stream.Close()
				_, _ = stream.ReceiveDatagram(context.Background())
				_, _ = stream.Write([]byte{0x3f, 8, 'x'})
				return
			case "/bad_capsule/":
				w.WriteHeader(200)
				return
			case "/inject/":
				w.Header().Set(http3.CapsuleProtocolHeader, "?1")
				w.WriteHeader(200)
				stream := w.(http3.HTTPStreamer).HTTPStream()
				defer stream.CancelRead(0)
				defer stream.CancelWrite(0)
				data, err := stream.ReceiveDatagram(context.Background())
				if err != nil {
					return
				}
				_ = stream.SendDatagram([]byte{})
				_ = stream.SendDatagram([]byte{1, 'x'})
				// Unknown capsule type with a short body must be ignored by the client.
				_, _ = stream.Write([]byte{0x3f, 3, 'a', 'b', 'c'})
				_ = stream.SendDatagram(data)
				_, _ = io.Copy(io.Discard, stream)
				return
			}
			_ = proxy.Proxy(w, req)
		})
		server := &http3.Server{TLSConfig: tlsConfig, EnableDatagrams: name != "no_datagrams", Handler: handler}
		go server.Serve(socket)
	}
	// A settings-only peer proves that HTTP Datagrams alone are insufficient.
	for _, mode := range []string{"no_extended_connect", "no_settings"} {
		socket, err := net.ListenPacket("udp", "127.0.0.1:0")
		must(err)
		endpoints[mode] = socket.LocalAddr().String()
		tlsConf := tlsConfig.Clone()
		tlsConf.NextProtos = []string{"h3"}
		listener, err := quic.Listen(socket, tlsConf, &quic.Config{EnableDatagrams: true})
		must(err)
		go func() {
			for {
				conn, err := listener.Accept(context.Background())
				if err != nil {
					return
				}
				go func() {
					if mode == "no_extended_connect" {
						stream, err := conn.OpenUniStreamSync(context.Background())
						if err != nil {
							return
						}
						_, _ = stream.Write([]byte{0, 4, 2, 0x33, 1})
					}
					<-conn.Context().Done()
				}()
			}
		}()
	}
	// Drop every eleventh encrypted packet in each direction. Nested QUIC must
	// recover without turning UDP datagrams into a reliable outer byte stream.
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	must(err)
	remote, err := net.ResolveUDPAddr("udp", endpoints["server"])
	must(err)
	back, err := net.DialUDP("udp", nil, remote)
	must(err)
	endpoints["loss_server"] = front.LocalAddr().String()
	var peerMu sync.Mutex
	var peer *net.UDPAddr
	var sent, received atomic.Uint64
	go func() {
		b := make([]byte, 65535)
		for {
			n, from, err := front.ReadFromUDP(b)
			if err != nil {
				return
			}
			peerMu.Lock()
			peer = from
			peerMu.Unlock()
			if sent.Add(1)%11 == 5 {
				continue
			}
			_, _ = back.Write(b[:n])
		}
	}()
	go func() {
		b := make([]byte, 65535)
		for {
			n, err := back.Read(b)
			if err != nil {
				return
			}
			if received.Add(1)%11 == 5 {
				continue
			}
			peerMu.Lock()
			dest := peer
			peerMu.Unlock()
			if dest != nil {
				_, _ = front.WriteToUDP(b[:n], dest)
			}
		}
	}()
	must(json.NewEncoder(os.Stdout).Encode(endpoints))
	// Keep fixture targets private to this subprocess and exit on test cleanup.
	select {}
}
