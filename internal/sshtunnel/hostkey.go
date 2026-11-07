package sshtunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Host-key failure codes. Callers that opted in with HostKeys may expose them
// as machine-readable faults; they never contain key material or host names.
const (
	// HostKeyMismatch: the host is known and the presented key is not trusted
	// for it, or the key is revoked. Never offered to the user.
	HostKeyMismatch = "ssh_host_key_mismatch"
	// HostKeyRejected: the user declined the offer for an unknown host.
	HostKeyRejected = "ssh_host_key_rejected"
	// HostKeyUnanswered: the offer expired or was withdrawn before an answer
	// (per-prompt timeout, round limit, deadline, network change, Stop or
	// connection loss).
	HostKeyUnanswered = "ssh_host_key_unanswered"
	// HostKeyUnknown: the host is unknown and no offer could be made.
	HostKeyUnknown = "ssh_host_key_unknown"
	// HostKeyCARequired: the selected known_hosts file has @cert-authority
	// lines and the presented key matched no entry. A file that delegates
	// trust to a CA never produces offers, because knownhosts CA patterns
	// match an exact port and so cannot prove a host outside the CA.
	HostKeyCARequired = "ssh_host_key_ca_required"
	// KnownHostsMissing: Options.ProfileOnly is set, the profile selects no
	// KnownHostsFile and the connection did not opt in with HostKeys.
	KnownHostsMissing = "ssh_known_hosts_missing"
)

// HostKeyKind is the Challenge kind of an accept-new host-key offer.
const HostKeyKind = "host_key"

// HostKeyAccept is the only answer that accepts a host-key offer.
const HostKeyAccept = "accept"

// ErrHostKeyDeclined is returned by a Prompt when the user explicitly declined
// a host-key offer, as opposed to a timeout or withdrawal.
var ErrHostKeyDeclined = errors.New("SSH host key declined")

// HostKeyError reports why host-key verification refused the connection.
type HostKeyError struct{ Code string }

func (e *HostKeyError) Error() string {
	switch e.Code {
	case HostKeyMismatch:
		return "SSH host key does not match the trusted key"
	case HostKeyRejected:
		return "SSH host key was not accepted"
	case HostKeyUnanswered:
		return "SSH host key offer was not answered"
	case HostKeyCARequired:
		return "SSH host key is not covered by the trusted certificate authority"
	case KnownHostsMissing:
		return "SSH known_hosts file must be selected"
	default:
		return "SSH host key is unknown"
	}
}

// HostKeyOffer describes the key presented by an unknown host. KnownHostsLine
// is the exact known_hosts line to persist after acceptance.
type HostKeyOffer struct {
	Host           string // host:port as dialed, host in ASCII lowercase
	KeyType        string // e.g. ssh-ed25519
	Fingerprint    string // SHA256:base64-without-padding
	KnownHostsLine string // "<host> <type> <base64>", without newline
}

// HostKeys opts a connection in to accept-new host-key handling. It is safe for
// concurrent use; keys accepted through an offer are remembered for the
// lifetime of this value, so reconnects of the same session do not re-offer.
// The known_hosts file from the profile, if any, is still consulted; without
// one, no default ~/.ssh/known_hosts is read.
type HostKeys struct {
	mu      sync.Mutex
	trusted map[string][][]byte // normalized host -> marshaled public keys
}

const maxTrustedHostKeys = 256 << 10

// ParseHostKeys validates caller-owned known_hosts lines. Only plain entries are
// accepted: comma-separated literal hosts ("name" or "[name]:port"), key type
// and base64 key, optionally followed by a comment. Markers, hashed hosts and
// patterns are rejected; import such files through KnownHostsFile instead.
func ParseHostKeys(data []byte) (*HostKeys, error) {
	if len(data) > maxTrustedHostKeys {
		return nil, fmt.Errorf("trusted host keys exceed %d bytes", maxTrustedHostKeys)
	}
	h := &HostKeys{trusted: map[string][][]byte{}}
	for n, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		bad := fmt.Errorf("invalid trusted host key at line %d", n+1)
		marker, hosts, key, _, rest, err := ssh.ParseKnownHosts(line)
		if err != nil || marker != "" || len(rest) != 0 || len(hosts) == 0 {
			return nil, bad
		}
		if _, ok := key.(*ssh.Certificate); ok {
			return nil, bad
		}
		for _, raw := range hosts {
			host, ok := canonicalHost(raw)
			if !ok {
				return nil, bad
			}
			h.add(host, key)
		}
	}
	return h, nil
}

func (h *HostKeys) add(host string, key ssh.PublicKey) {
	blob := key.Marshal()
	for _, k := range h.trusted[host] {
		if bytes.Equal(k, blob) {
			return
		}
	}
	h.trusted[host] = append(h.trusted[host], blob)
}

// lookup returns the trusted keys for a normalized host.
func (h *HostKeys) lookup(host string) []ssh.PublicKey {
	h.mu.Lock()
	defer h.mu.Unlock()
	var keys []ssh.PublicKey
	for _, blob := range h.trusted[host] {
		if k, err := ssh.ParsePublicKey(blob); err == nil {
			keys = append(keys, k)
		}
	}
	return keys
}

// canonicalHost maps a literal known_hosts host to lowercase
// knownhosts.Normalize form.
func canonicalHost(raw string) (string, bool) {
	if !safeHost(raw) {
		return "", false
	}
	raw = asciiLower(raw)
	address := net.JoinHostPort(raw, "22")
	if strings.HasPrefix(raw, "[") {
		host, port, err := net.SplitHostPort(raw)
		if err != nil || host == "" {
			return "", false
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", false
		}
		address = net.JoinHostPort(host, port)
	} else if strings.ContainsAny(raw, "[]") {
		return "", false
	}
	return knownhosts.Normalize(address), true
}

// asciiLower lowercases ASCII letters only. OpenSSH lowercases host names
// before matching and writing known_hosts, while x/crypto knownhosts compares
// bytes, so every lookup, offer and stored line uses this form.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// safeHost admits only literal host characters, so an emitted known_hosts line
// can never contain a pattern, negation, hash, marker, list or whitespace.
func safeHost(s string) bool {
	if s == "" || len(s) > 300 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(".-_:[]%", r):
		default:
			return false
		}
	}
	return true
}

// verifier implements accept-new for one connection attempt.
type verifier struct {
	keys    *HostKeys
	file    ssh.HostKeyCallback // nil without a selected known_hosts file
	ca      bool                // the file has @cert-authority lines
	upper   bool                // the file has a plain host pattern with A-Z
	ctx     context.Context
	prompt  Prompt // already bounded by the attempt; nil means no offers
	mu      sync.Mutex
	outcome *HostKeyError
}

func (v *verifier) fail(code string) error {
	e := &HostKeyError{Code: code}
	v.mu.Lock()
	v.outcome = e
	v.mu.Unlock()
	return e
}

func (v *verifier) result() *HostKeyError {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.outcome
}

// known returns the trusted keys for address from both sources. The file is
// asked with the lowercase address and, if different, the address as dialed,
// so an entry in either case is honoured. A non-nil error means the file
// database could not answer.
func (v *verifier) known(address string, remote net.Addr, key ssh.PublicKey) (match, revoked bool, want []ssh.PublicKey, err error) {
	lower := asciiLower(address)
	if v.file != nil {
		candidates := []string{lower}
		if address != lower {
			candidates = append(candidates, address)
		}
		for _, candidate := range candidates {
			e := v.file(candidate, remote, key)
			var ke *knownhosts.KeyError
			var re *knownhosts.RevokedError
			switch {
			case e == nil:
				match = true
			case errors.As(e, &re):
				return false, true, nil, nil
			case errors.As(e, &ke):
				for _, k := range ke.Want {
					want = append(want, k.Key)
				}
			default:
				return false, false, nil, e
			}
		}
	}
	blob := key.Marshal()
	for _, k := range v.keys.lookup(knownhosts.Normalize(lower)) {
		want = append(want, k)
		if bytes.Equal(k.Marshal(), blob) {
			match = true
		}
	}
	return match, false, want, nil
}

func (v *verifier) check(address string, remote net.Addr, key ssh.PublicKey) error {
	match, revoked, want, err := v.known(address, remote, key)
	switch {
	case revoked:
		return v.fail(HostKeyMismatch)
	case err != nil:
		return err
	case match:
		return nil
	case len(want) > 0:
		return v.fail(HostKeyMismatch)
	case v.ca:
		return v.fail(HostKeyCARequired)
	}
	if _, ok := key.(*ssh.Certificate); ok || v.prompt == nil || v.upper {
		return v.fail(HostKeyUnknown)
	}
	host, port, err := net.SplitHostPort(asciiLower(address))
	if err != nil || !safeHost(host) || strings.ContainsAny(host, "[]") {
		return v.fail(HostKeyUnknown)
	}
	address = net.JoinHostPort(host, port)
	offer := HostKeyOffer{
		Host:           address,
		KeyType:        key.Type(),
		Fingerprint:    ssh.FingerprintSHA256(key),
		KnownHostsLine: knownhosts.Line([]string{address}, key),
	}
	answers, err := v.prompt(v.ctx, Challenge{Kind: HostKeyKind, HostKey: &offer})
	if errors.Is(err, ErrHostKeyDeclined) {
		return v.fail(HostKeyRejected)
	}
	if err != nil {
		return v.fail(HostKeyUnanswered)
	}
	if len(answers) != 1 || answers[0] != HostKeyAccept {
		return v.fail(HostKeyRejected)
	}
	v.keys.mu.Lock()
	v.keys.add(knownhosts.Normalize(address), key)
	v.keys.mu.Unlock()
	return nil
}

// hostKeyPreference is the first-contact order: Ed25519, then ECDSA, then RSA,
// so a new host is not pinned to RSA because the library lists it first.
var hostKeyPreference = []string{
	ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA,
	ssh.CertAlgoED25519v01, ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01,
	ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01,
}

// algorithms prefers host-key algorithms for key types already trusted for the
// host, like OpenSSH, so an additional server key type is not mistaken for a
// changed key. Plain-key algorithms follow in hostKeyPreference order, then
// certificate algorithms. A file with @cert-authority lines keeps the library
// order (certificates first), because knownhosts also counts authority keys as
// known keys for the host; such a file never produces offers.
func (v *verifier) algorithms(address string, remote net.Addr) []string {
	if v.ca {
		return nil
	}
	_, probe, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(probe)
	if err != nil {
		return nil
	}
	_, _, want, err := v.known(address, remote, signer.PublicKey())
	if err != nil {
		return nil
	}
	var supported []string
	for _, name := range append(hostKeyPreference, ssh.SupportedAlgorithms().HostKeys...) {
		if (name == ssh.KeyAlgoRSA || contains(ssh.SupportedAlgorithms().HostKeys, name)) && !contains(supported, name) {
			supported = append(supported, name)
		}
	}
	var known, plain, certs []string
	for _, k := range want {
		names := []string{k.Type()}
		if k.Type() == ssh.KeyAlgoRSA {
			names = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
		}
		for _, name := range names {
			if contains(supported, name) && !contains(known, name) {
				known = append(known, name)
			}
		}
	}
	for _, name := range supported {
		if contains(known, name) {
			continue
		}
		if strings.HasSuffix(name, "-cert-v01@openssh.com") {
			certs = append(certs, name)
		} else {
			plain = append(plain, name)
		}
	}
	return append(append(known, plain...), certs...)
}

// inspectHosts reports whether known_hosts data has @cert-authority lines and
// whether a plain (unhashed) host pattern contains an uppercase letter. Such a
// pattern matches case-insensitively in OpenSSH but not in x/crypto
// knownhosts, so the file cannot prove a host unknown and offers are disabled.
func inspectHosts(data []byte) (authority, upper bool) {
	for _, line := range bytes.Split(data, []byte("\n")) {
		fields := bytes.Fields(line)
		if len(fields) == 0 || fields[0][0] == '#' {
			continue
		}
		hosts := fields[0]
		if hosts[0] == '@' {
			authority = authority || bytes.HasPrefix(hosts, []byte("@cert-authority"))
			if len(fields) < 2 {
				continue
			}
			hosts = fields[1]
		}
		for _, pattern := range bytes.Split(hosts, []byte(",")) {
			if !bytes.HasPrefix(pattern, []byte("|")) && bytes.ContainsFunc(pattern, func(r rune) bool { return r >= 'A' && r <= 'Z' }) {
				upper = true
			}
		}
	}
	return authority, upper
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
