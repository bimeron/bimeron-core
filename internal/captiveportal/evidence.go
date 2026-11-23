// Package captiveportal classifies evidence from existing upstream handshakes.
package captiveportal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	utls "github.com/refraction-networking/utls"
)

type attemptKey struct{}

type Attempt struct {
	mu        sync.Mutex
	localDNS  map[string]struct{}
	suspected atomic.Bool
}

func Observe(ctx context.Context) (context.Context, *Attempt) {
	a := new(Attempt)
	return context.WithValue(ctx, attemptKey{}, a), a
}

func (a *Attempt) Suspected() bool { return a.suspected.Load() }

func Observing(ctx context.Context) bool { return ctx.Value(attemptKey{}) != nil }

// CopyObservation preserves setup evidence when a request belongs to a
// different cancellation lifetime than the caller.
func CopyObservation(lifetime, setup context.Context) context.Context {
	if a := setup.Value(attemptKey{}); a != nil {
		return context.WithValue(lifetime, attemptKey{}, a)
	}
	return lifetime
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// Resolved records the selected address of a named upstream, before dialing.
func Resolved(ctx context.Context, host, address string) {
	a, _ := ctx.Value(attemptKey{}).(*Attempt)
	if a == nil {
		return
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return
	}
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil {
		return
	}
	ip := endpoint.Addr().Unmap()
	if !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !sharedAddressSpace.Contains(ip) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.localDNS == nil {
		a.localDNS = make(map[string]struct{})
	}
	a.localDNS[address] = struct{}{}
}

// Failed is called only at a physical upstream handshake. HTTP or hostname
// mismatch is evidence on its own. Other failures need a matching DNS answer.
func Failed(ctx context.Context, endpoint string, strong bool) {
	a, _ := ctx.Value(attemptKey{}).(*Attempt)
	if a == nil || ctx.Err() == context.Canceled {
		return
	}
	if !strong {
		a.mu.Lock()
		_, strong = a.localDNS[endpoint]
		a.mu.Unlock()
	}
	if strong {
		a.suspected.Store(true)
	}
}

func TLSFailed(ctx context.Context, conn net.Conn, serverName string, err error) {
	if !Observing(ctx) {
		return
	}
	var hostname x509.HostnameError
	var header tls.RecordHeaderError
	var uheader utls.RecordHeaderError
	strong := errors.As(err, &hostname) ||
		errors.As(err, &header) && string(header.RecordHeader[:]) == "HTTP/" ||
		errors.As(err, &uheader) && string(uheader.RecordHeader[:]) == "HTTP/"
	if !strong && serverName != "" {
		// Some system trust stores report trust failure before checking the name.
		var verification *tls.CertificateVerificationError
		var uverification *utls.CertificateVerificationError
		var presented []*x509.Certificate
		switch {
		case errors.As(err, &verification):
			presented = verification.UnverifiedCertificates
		case errors.As(err, &uverification):
			presented = uverification.UnverifiedCertificates
		}
		if len(presented) > 0 {
			strong = errors.As(presented[0].VerifyHostname(serverName), &hostname)
		}
	}
	Failed(ctx, conn.RemoteAddr().String(), strong)
}

// RedirectStatus recognizes redirects and the HTTP network-authentication code
// on handshakes that already expect an HTTP response.
func RedirectStatus(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308 || code == 511
}
