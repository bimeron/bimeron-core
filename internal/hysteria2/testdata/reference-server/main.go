package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/apernet/hysteria/core/v2/server"
	"io"
	"math/big"
	"net"
	"time"
)

type auth struct{}

func (auth) Authenticate(_ net.Addr, password string, _ uint64) (bool, string) {
	return password == "fixture-pass", "probe"
}
func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer tcp.Close()
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udp.WriteTo(b[:n], a)
		}
	}()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	s, err := server.NewServer(&server.Config{Conn: listener, Authenticator: auth{}, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}})
	if err != nil {
		panic(err)
	}
	defer s.Close()
	disabledListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	disabled, err := server.NewServer(&server.Config{Conn: disabledListener, Authenticator: auth{}, DisableUDP: true, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}})
	if err != nil {
		panic(err)
	}
	defer disabled.Close()
	go func() { _ = disabled.Serve() }()
	config, _ := json.Marshal(map[string]string{"server": listener.LocalAddr().String(), "udp_disabled_server": disabledListener.LocalAddr().String(), "tcp": tcp.Addr().String(), "udp": udp.LocalAddr().String(), "certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))})
	fmt.Println(string(config))
	if err = s.Serve(); err != nil {
		panic(err)
	}
}
