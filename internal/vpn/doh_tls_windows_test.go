package vpn

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestDoHNativeTrust(t *testing.T) {
	testDoHTrust(t, func(root *x509.Certificate) func(tls.ConnectionState) error {
		store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { windows.CertCloseStore(store, 0) })
		cert, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &root.Raw[0], uint32(len(root.Raw)))
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CertFreeCertificateContext(cert)
		if err := windows.CertAddCertificateContextToStore(store, cert, windows.CERT_STORE_ADD_ALWAYS, nil); err != nil {
			t.Fatal(err)
		}

		// CERT_CHAIN_ENGINE_CONFIG, with an exclusive in-memory root for this test.
		var config struct {
			size                                             uint32
			restrictedRoot, restrictedTrust, restrictedOther windows.Handle
			additionalCount                                  uint32
			additionalStores                                 uintptr
			flags, timeout, cacheSize, cycleModulus          uint32
			exclusiveRoot, exclusiveTrustedPeople            windows.Handle
			exclusiveFlags                                   uint32
		}
		config.size = uint32(unsafe.Sizeof(config))
		config.exclusiveRoot = store
		var engine windows.Handle
		crypt := windows.NewLazySystemDLL("crypt32.dll")
		ok, _, err := crypt.NewProc("CertCreateCertificateChainEngine").Call(uintptr(unsafe.Pointer(&config)), uintptr(unsafe.Pointer(&engine)))
		if ok == 0 {
			t.Fatal(err)
		}
		t.Cleanup(func() { crypt.NewProc("CertFreeCertificateChainEngine").Call(uintptr(engine)) })
		return func(state tls.ConnectionState) error { return verifyWindowsDoHChain(state, engine) }
	})
}
