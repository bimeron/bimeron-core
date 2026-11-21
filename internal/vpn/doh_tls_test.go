//go:build windows || darwin

package vpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testDoHTrust(t *testing.T, native func(*x509.Certificate) func(tls.ConnectionState) error) {
	var aiaConnections atomic.Int32
	var aiaIssuer atomic.Pointer[x509.Certificate]
	witness := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		issuer := aiaIssuer.Load()
		if issuer == nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = w.Write(issuer.Raw)
	}))
	witness.Config.ConnState = func(_ net.Conn, status http.ConnState) {
		if status == http.StateNew {
			aiaConnections.Add(1)
		}
	}
	witness.Start()
	defer witness.Close()

	now := time.Now()
	issue := func(serial int64, subject string, ca bool, parent *x509.Certificate, signer *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: subject},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature,
		}
		if ca {
			cert.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}
		if parent == nil {
			parent, signer = cert, key
		}
		if !ca {
			cert.DNSNames = []string{subject}
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			cert.IssuingCertificateURL = []string{witness.URL + "/issuer.cer"}
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, parent, &key.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return parsed, key
	}
	root, rootKey := issue(1, "Bimeron DoH test root", true, nil, nil)
	issuer, issuerKey := issue(2, "Bimeron DoH test issuer", true, root, rootKey)
	aiaIssuer.Store(issuer)
	leaf, leafKey := issue(3, "doh.test", false, issuer, issuerKey)
	trusted := native(root)
	untrusted := dohTLSConfig().VerifyConnection

	check := func(name string, chain [][]byte, verify func(tls.ConnectionState) error, wantSuccess bool) {
		t.Run(name, func(t *testing.T) {
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: leafKey}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := listener.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_ = c.(*tls.Conn).Handshake()
			}()
			cfg := dohTLSConfig()
			cfg.ServerName = "doh.test"
			if name == "wrong hostname" {
				cfg.ServerName = "wrong.test"
			}
			cfg.VerifyConnection = verify
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", listener.Addr().String(), cfg)
			if c != nil {
				c.Close()
			}
			listener.Close()
			<-done
			if (err == nil) != wantSuccess {
				t.Fatalf("TLS result = %v, want success = %t", err, wantSuccess)
			}
		})
	}
	check("cold missing issuer", [][]byte{leaf.Raw}, trusted, false)
	check("trusted full chain", [][]byte{leaf.Raw, issuer.Raw}, trusted, true)
	check("wrong hostname", [][]byte{leaf.Raw, issuer.Raw}, trusted, false)
	check("untrusted full chain", [][]byte{leaf.Raw, issuer.Raw, root.Raw}, untrusted, false)
	if got := aiaConnections.Load(); got != 0 {
		t.Fatalf("AIA listener accepted %d connection(s)", got)
	}
}
