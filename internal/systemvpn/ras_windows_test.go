//go:build windows

package systemvpn

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestAsyncPortNotAllocatedIsPendingUntilTerminalCallback(t *testing.T) {
	a := &rasAttempt{}
	if state, err := a.invalidStatus(); err != nil || state.code != 0 {
		t.Fatal("early invalid handle was treated as failure", state, err)
	}
	a.closing = true
	if _, err := a.invalidStatus(); err != nil {
		t.Fatal("cancellation discarded a still-pending dial", err)
	}
	a.latest = connectionState{code: 691}
	a.closing = false
	if state, err := a.invalidStatus(); err != nil || state.code != 691 {
		t.Fatal("lost asynchronous auth error", state, err)
	}
	a.closing = true
	if _, err := a.invalidStatus(); !errors.Is(err, errInvalidHandle) {
		t.Fatal("failed unallocated port not released", err)
	}
	a = &rasAttempt{closing: true, hangupAccepted: true}
	if _, err := a.invalidStatus(); !errors.Is(err, errInvalidHandle) {
		t.Fatal("acknowledged hangup not finalized", err)
	}
	a = &rasAttempt{connected: true}
	if _, err := a.invalidStatus(); !errors.Is(err, errInvalidHandle) {
		t.Fatal("lost connected handle treated as startup", err)
	}
}

func validEntry() rasEntry {
	e := rasEntry{Type: 2, VPNStrategy: 7, CustomAuthKey: 26, Options: 0x20000 | 0x10, Options2: 0x2000, NetProtocols: 0xc, EncryptionType: 1}
	copy(e.PhoneNumber[:], windows.StringToUTF16(testConfig().ServerName))
	return e
}

func TestRejectUnsafeNativeProfiles(t *testing.T) {
	if err := validateEntry(validEntry(), testConfig()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*rasEntry){
		"protocol fallback":   func(e *rasEntry) { e.VPNStrategy = 8 },
		"no EAP":              func(e *rasEntry) { e.Options &= ^uint32(0x20000) },
		"other EAP":           func(e *rasEntry) { e.CustomAuthKey = 13 },
		"password fallback":   func(e *rasEntry) { e.Options |= 0x40000 },
		"certificate bypass":  func(e *rasEntry) { e.Options2 |= 0x40000 },
		"PSK":                 func(e *rasEntry) { e.Options2 |= 0x800000 },
		"system reconnect":    func(e *rasEntry) { e.Options2 |= 0x100 },
		"redial":              func(e *rasEntry) { e.RedialCount = 3 },
		"wrong identity":      func(e *rasEntry) { e.PhoneNumber[0] = 'x' },
		"custom identity":     func(e *rasEntry) { e.IDr[0] = 'x' },
		"split IPv4":          func(e *rasEntry) { e.Options &= ^uint32(0x10) },
		"split IPv6":          func(e *rasEntry) { e.Options2 &= ^uint32(0x2000) },
		"missing IPv6":        func(e *rasEntry) { e.NetProtocols = 4 },
		"optional encryption": func(e *rasEntry) { e.EncryptionType = 3 },
		"script":              func(e *rasEntry) { e.Script[0] = 'x' },
		"custom DLL":          func(e *rasEntry) { e.CustomDialDLL[0] = 'x' },
		"alternate server":    func(e *rasEntry) { e.AlternateOffset = 100 },
		"logon credentials":   func(e *rasEntry) { e.Options |= 0x4000 },
		"always on":           func(e *rasEntry) { e.Options2 |= 0x20000000 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			e := validEntry()
			change(&e)
			if validateEntry(e, testConfig()) == nil {
				t.Fatal("unsafe profile accepted")
			}
		})
	}
}

func TestRASABI(t *testing.T) {
	if unsafe.Offsetof(rasStatus{}.LocalEndpoint) != 564 || unsafe.Offsetof(rasStatus{}.RemoteEndpoint) != 584 {
		t.Fatal("incorrect tunnel endpoint alignment")
	}
	// Windows SDK ras.h: pack(4), Windows 10 structures, both pointer widths.
	if unsafe.Sizeof(rasEntry{}) != 6724 || unsafe.Offsetof(rasEntry{}.VPNStrategy) != 4044 || unsafe.Offsetof(rasEntry{}.Options2) != 4048 {
		t.Fatalf("RASENTRY layout: size=%d strategy=%d options2=%d", unsafe.Sizeof(rasEntry{}), unsafe.Offsetof(rasEntry{}.VPNStrategy), unsafe.Offsetof(rasEntry{}.Options2))
	}
	if unsafe.Offsetof(rasConnection{}.Handle) != 4 || unsafe.Offsetof(rasEapIdentity{}.Size) != 516 || unsafe.Sizeof(rasStatus{}) != 608 {
		t.Fatal("incorrect packed RAS layout")
	}
	if unsafe.Sizeof(rasDialParams{}) != 2104+2*unsafe.Sizeof(uintptr(0)) || unsafe.Sizeof(rasDialExtensions{}) != 20+5*unsafe.Sizeof(uintptr(0)) || unsafe.Sizeof(rasConnection{}) != 1380+unsafe.Sizeof(uintptr(0)) {
		t.Fatalf("dial layouts: %d %d", unsafe.Sizeof(rasDialParams{}), unsafe.Sizeof(rasDialExtensions{}))
	}
}

func TestNativeInvalidHandleReadOnly(t *testing.T) {
	if rasGetConnectStatus.Find() != nil {
		t.Skip("RAS unavailable")
	}
	_, err := (&windowsDriver{}).status(0)
	if err == nil {
		t.Fatal("native RAS accepted null handle")
	}
}

func TestNativeDefaultEntryReadOnly(t *testing.T) {
	if rasGetEntryProperties.Find() != nil {
		t.Skip("RAS unavailable")
	}
	// An empty entry name requests defaults. Use a temporary empty phonebook;
	// this never reads user credentials or creates an installed VPN profile.
	book := filepath.Join(t.TempDir(), "rasphone.pbk")
	if err := os.WriteFile(book, nil, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := (&windowsDriver{phonebook: book}).entry(Config{})
	if err != nil {
		t.Fatal("native RAS did not accept the structure layout", err)
	}
	if e.Size != uint32(unsafe.Sizeof(e)) {
		t.Fatal("unexpected native RAS entry size", e.Size)
	}
}

// Acceptance 6: pure HangUp classification, no native calls.
func TestClassifyHangup(t *testing.T) {
	terminal := map[string]func() *rasAttempt{
		"callback error": func() *rasAttempt { return &rasAttempt{closing: true, latest: connectionState{code: 775}} },
		"disconnected": func() *rasAttempt {
			return &rasAttempt{closing: true, latest: connectionState{state: stateDisconnected}}
		},
		"was connected": func() *rasAttempt { return &rasAttempt{closing: true, connected: true} },
	}
	for _, code := range []uint32{6, 668} {
		for name, attempt := range terminal {
			a := attempt()
			err := classifyHangup(code, a)
			if !errors.Is(err, errHangupNoConnection) || errors.Is(err, errInvalidHandle) || a.hangupAccepted {
				t.Fatal(code, name, err, a.hangupAccepted)
			}
		}
		for name, a := range map[string]*rasAttempt{"pending": {closing: true, latest: connectionState{state: 1}}, "untracked": nil} {
			if err := classifyHangup(code, a); !errors.Is(err, errDialPending) {
				t.Fatal(code, name, err)
			}
		}
	}
	a := &rasAttempt{closing: true, latest: connectionState{code: 775}}
	if err := classifyHangup(0, a); err != nil || !a.hangupAccepted {
		t.Fatal("HangUp 0 not accepted", err)
	}
	for _, code := range []uint32{5, 87, 603, 632, 775} {
		err := classifyHangup(code, &rasAttempt{latest: connectionState{code: 775}})
		if err == nil || errors.Is(err, errInvalidHandle) || errors.Is(err, errHangupNoConnection) || errors.Is(err, errDialPending) {
			t.Fatal(code, err)
		}
	}
}

// Acceptance 7: pure enumeration classification, no native calls.
func TestOwnedIn(t *testing.T) {
	const owned = 196608
	buffer := func(handles ...uintptr) []rasConnection {
		c := make([]rasConnection, ownedEnumCapacity)
		for i, h := range handles {
			c[i].Handle.set(h)
		}
		return c
	}
	if present, err := ownedIn(0, buffer(), 0, owned); present || err != nil {
		t.Fatal("empty list", present, err)
	}
	if present, err := ownedIn(0, buffer(1, 2, 3), 3, owned); present || err != nil {
		t.Fatal("unrelated handles", present, err)
	}
	// A stale entry beyond count must not count as present.
	if present, err := ownedIn(0, buffer(1, owned), 1, owned); present || err != nil {
		t.Fatal("entry beyond count", present, err)
	}
	for i := 0; i < ownedEnumCapacity; i++ {
		handles := make([]uintptr, ownedEnumCapacity)
		for j := range handles {
			handles[j] = uintptr(j + 1)
		}
		handles[i] = owned
		if present, err := ownedIn(0, buffer(handles...), ownedEnumCapacity, owned); !present || err != nil {
			t.Fatal("owned at index", i, present, err)
		}
	}
	for _, code := range []uint32{603, 87, 5} {
		if _, err := ownedIn(code, buffer(owned), 1, owned); err == nil {
			t.Fatal("accepted enumeration error", code)
		}
	}
	if _, err := ownedIn(0, buffer(1), ownedEnumCapacity+1, owned); err == nil {
		t.Fatal("accepted count beyond buffer")
	}
}
