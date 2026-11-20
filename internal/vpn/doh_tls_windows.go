package vpn

import (
	"crypto/tls"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dohChainCacheOnlyURLRetrieval = 0x00000004
	dohChainDisableAIA            = 0x00002000
	dohChainRevocationCacheOnly   = 0x80000000
)

func verifyDoHChain(state tls.ConnectionState) error {
	return verifyWindowsDoHChain(state, 0)
}

func verifyWindowsDoHChain(state tls.ConnectionState, engine windows.Handle) error {
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)

	var leaf *windows.CertContext
	for i, cert := range state.PeerCertificates {
		ctx, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &cert.Raw[0], uint32(len(cert.Raw)))
		if err != nil {
			return err
		}
		var added **windows.CertContext
		if i == 0 {
			added = &leaf
		}
		err = windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_ALWAYS, added)
		windows.CertFreeCertificateContext(ctx)
		if err != nil {
			return err
		}
		if i == 0 {
			defer windows.CertFreeCertificateContext(leaf)
		}
	}

	serverAuth := []byte("1.3.6.1.5.5.7.3.1\x00")
	usage := &serverAuth[0]
	params := windows.CertChainPara{RequestedUsage: windows.CertUsageMatch{
		Usage: windows.CertEnhKeyUsage{Length: 1, UsageIdentifiers: &usage},
	}}
	params.Size = uint32(unsafe.Sizeof(params))
	var chain *windows.CertChainContext
	flags := uint32(dohChainCacheOnlyURLRetrieval | dohChainDisableAIA | dohChainRevocationCacheOnly)
	if err := windows.CertGetCertificateChain(engine, leaf, nil, store, &params, flags, 0, &chain); err != nil {
		return err
	}
	defer windows.CertFreeCertificateChain(chain)

	hostname, err := windows.UTF16PtrFromString(state.ServerName)
	if err != nil {
		return err
	}
	ssl := windows.SSLExtraCertChainPolicyPara{AuthType: windows.AUTHTYPE_SERVER, ServerName: hostname}
	ssl.Size = uint32(unsafe.Sizeof(ssl))
	policy := windows.CertChainPolicyPara{ExtraPolicyPara: windows.Pointer(unsafe.Pointer(&ssl))}
	policy.Size = uint32(unsafe.Sizeof(policy))
	status := windows.CertChainPolicyStatus{}
	status.Size = uint32(unsafe.Sizeof(status))
	if err := windows.CertVerifyCertificateChainPolicy(windows.CERT_CHAIN_POLICY_SSL, chain, &policy, &status); err != nil {
		return err
	}
	if status.Error != 0 {
		return fmt.Errorf("Windows TLS chain policy rejected certificate (0x%08x)", status.Error)
	}
	return nil
}
