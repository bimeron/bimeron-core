//go:build darwin && (!ios || cgo)

package vpn

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type appleTrustAPI struct {
	callbacks    uintptr
	anchor       func(uintptr, uintptr) int32
	data         func(uintptr, *byte, int) uintptr
	string       func(uintptr, string, uint32) uintptr
	array        func(uintptr, *uintptr, int, uintptr) uintptr
	release      func(uintptr)
	certificate  func(uintptr, uintptr) uintptr
	sslPolicy    func(bool, uintptr) uintptr
	trust        func(uintptr, uintptr, *uintptr) int32
	networkFetch func(uintptr, bool) int32
	evaluate     func(uintptr, uintptr) bool
}

var loadAppleTrust = sync.OnceValues(func() (*appleTrustAPI, error) {
	const frameworks = "/System/Library/Frameworks/"
	cf, err := purego.Dlopen(frameworks+"CoreFoundation.framework/CoreFoundation", purego.RTLD_LOCAL|purego.RTLD_NOW)
	if err != nil {
		return nil, err
	}
	sec, err := purego.Dlopen(frameworks+"Security.framework/Security", purego.RTLD_LOCAL|purego.RTLD_NOW)
	if err != nil {
		purego.Dlclose(cf)
		return nil, err
	}
	a := new(appleTrustAPI)
	a.callbacks, err = purego.Dlsym(cf, "kCFTypeArrayCallBacks")
	if err != nil {
		purego.Dlclose(sec)
		purego.Dlclose(cf)
		return nil, err
	}
	for _, symbol := range []struct {
		lib  uintptr
		name string
		fn   any
	}{
		{cf, "CFDataCreate", &a.data},
		{cf, "CFStringCreateWithCString", &a.string},
		{cf, "CFArrayCreate", &a.array},
		{cf, "CFRelease", &a.release},
		{sec, "SecCertificateCreateWithData", &a.certificate},
		{sec, "SecPolicyCreateSSL", &a.sslPolicy},
		{sec, "SecTrustCreateWithCertificates", &a.trust},
		{sec, "SecTrustSetNetworkFetchAllowed", &a.networkFetch},
		{sec, "SecTrustSetAnchorCertificates", &a.anchor},
		{sec, "SecTrustEvaluateWithError", &a.evaluate},
	} {
		address, err := purego.Dlsym(symbol.lib, symbol.name)
		if err != nil {
			purego.Dlclose(sec)
			purego.Dlclose(cf)
			return nil, err
		}
		purego.RegisterFunc(symbol.fn, address)
	}
	return a, nil
})

func verifyDoHChain(state tls.ConnectionState) error {
	return verifyAppleDoHChain(state, nil)
}

func verifyAppleDoHChain(state tls.ConnectionState, anchor *x509.Certificate) error {
	a, err := loadAppleTrust()
	if err != nil {
		return err
	}

	certs := make([]uintptr, 0, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		data := a.data(0, unsafe.SliceData(cert.Raw), len(cert.Raw))
		runtime.KeepAlive(cert)
		if data == 0 {
			return errors.New("could not allocate Apple TLS certificate data")
		}
		ref := a.certificate(0, data)
		a.release(data)
		if ref == 0 {
			return errors.New("could not import Apple TLS certificate")
		}
		defer a.release(ref)
		certs = append(certs, ref)
	}
	// The slice of certificate references remains owned until trust evaluation ends.
	chain := a.array(0, unsafe.SliceData(certs), len(certs), a.callbacks)
	if chain == 0 {
		return errors.New("could not allocate Apple TLS chain")
	}
	defer a.release(chain)

	const cfStringUTF8 = 0x08000100
	name := a.string(0, state.ServerName, cfStringUTF8)
	if name == 0 {
		return errors.New("could not allocate Apple TLS hostname")
	}
	defer a.release(name)
	policy := a.sslPolicy(true, name)
	if policy == 0 {
		return errors.New("could not create Apple TLS server policy")
	}
	defer a.release(policy)
	var trust uintptr
	if status := a.trust(chain, policy, &trust); status != 0 {
		return fmt.Errorf("could not create Apple TLS trust evaluation (%d)", status)
	}
	defer a.release(trust)
	if anchor != nil {
		data := a.data(0, unsafe.SliceData(anchor.Raw), len(anchor.Raw))
		runtime.KeepAlive(anchor)
		if data == 0 {
			return errors.New("could not allocate Apple trust anchor data")
		}
		ref := a.certificate(0, data)
		a.release(data)
		if ref == 0 {
			return errors.New("could not import Apple trust anchor")
		}
		defer a.release(ref)
		anchors := a.array(0, &ref, 1, a.callbacks)
		if anchors == 0 {
			return errors.New("could not allocate Apple trust anchors")
		}
		defer a.release(anchors)
		if status := a.anchor(trust, anchors); status != 0 {
			return fmt.Errorf("could not set Apple evaluation trust anchor (%d)", status)
		}
	}
	if status := a.networkFetch(trust, false); status != 0 {
		return fmt.Errorf("could not disable Apple TLS network fetch (%d)", status)
	}
	if !a.evaluate(trust, 0) {
		return errors.New("Apple TLS trust policy rejected certificate")
	}
	return nil
}
