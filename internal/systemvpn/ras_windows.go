//go:build windows

package systemvpn

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	rasDLL                 = windows.NewLazySystemDLL("rasapi32.dll")
	rasGetEntryProperties  = rasDLL.NewProc("RasGetEntryPropertiesW")
	rasEnumConnections     = rasDLL.NewProc("RasEnumConnectionsW")
	rasGetEntryDialParams  = rasDLL.NewProc("RasGetEntryDialParamsW")
	rasGetEapUserIdentity  = rasDLL.NewProc("RasGetEapUserIdentityW")
	rasFreeEapUserIdentity = rasDLL.NewProc("RasFreeEapUserIdentityW")
	rasDial                = rasDLL.NewProc("RasDialW")
	rasGetConnectStatus    = rasDLL.NewProc("RasGetConnectStatusW")
	rasHangUp              = rasDLL.NewProc("RasHangUpW")
	// One process-wide callback avoids leaking one Windows callback thunk per
	// connection. RAS runs asynchronously; authoritative state is polled below.
	rasNotifier = syscall.NewCallback(func(id uintptr, _ uint32, _ uintptr, _ uint32, state, code, _ uint32) uintptr {
		if value, ok := rasAttempts.Load(id); ok {
			a := value.(*rasAttempt)
			a.mu.Lock()
			a.latest = connectionState{state: state, code: code}
			a.connected = a.connected || state == stateConnected
			a.mu.Unlock()
		}
		return 1
	})
	rasAttempts  sync.Map
	rasAttemptID atomic.Uintptr
)

const pointerWords = unsafe.Sizeof(uintptr(0)) / 4

// ras.h uses #pragma pack(4), including pointer fields on amd64/arm64.
// Store pointers as DWORD arrays so Go cannot insert 8-byte alignment padding.
type packedPointer [pointerWords]uint32

func (p *packedPointer) set(v uintptr) {
	p[0] = uint32(v)
	words := p[:]
	if len(words) == 2 {
		words[1] = uint32(uint64(v) >> 32)
	}
}

func (p packedPointer) get() uintptr {
	v := uint64(p[0])
	if len(p) == 2 {
		v |= uint64(p[len(p)-1]) << 32
	}
	return uintptr(v)
}

type rasEntry struct {
	Size, Options, CountryID, CountryCode                               uint32
	AreaCode                                                            [11]uint16
	PhoneNumber                                                         [129]uint16
	AlternateOffset                                                     uint32
	Addresses                                                           [5][4]byte
	FrameSize, NetProtocols, FramingProtocol                            uint32
	Script, AutodialDLL, AutodialFunc                                   [260]uint16
	DeviceType                                                          [17]uint16
	DeviceName                                                          [129]uint16
	X25PadType                                                          [33]uint16
	X25Address, X25Facilities, X25UserData                              [201]uint16
	Channels, Reserved1, Reserved2                                      uint32
	SubEntries, DialMode, DialExtraPercent, DialExtraSampleSeconds      uint32
	HangUpExtraPercent, HangUpExtraSampleSeconds, IdleDisconnectSeconds uint32
	Type, EncryptionType, CustomAuthKey                                 uint32
	GUID                                                                windows.GUID
	CustomDialDLL                                                       [260]uint16
	VPNStrategy, Options2, Options3                                     uint32
	DNSSuffix                                                           [256]uint16
	TCPWindowSize                                                       uint32
	PrerequisitePBK                                                     [260]uint16
	PrerequisiteEntry                                                   [257]uint16
	RedialCount, RedialPause                                            uint32
	IPv6DNS, IPv6DNSAlt                                                 [16]byte
	IPv4Metric, IPv6Metric                                              uint32
	IPv6Address                                                         [16]byte
	IPv6PrefixLength, NetworkOutageTime                                 uint32
	IDi, IDr                                                            [257]uint16
	IsIMSConfig, IDiType, IDrType, DisableFragmentation                 uint32
}

type rasConnection struct {
	Size          uint32
	Handle        packedPointer
	EntryName     [257]uint16
	DeviceType    [17]uint16
	DeviceName    [129]uint16
	Phonebook     [260]uint16
	SubEntry      uint32
	GUID          windows.GUID
	Flags         uint32
	LUID          [2]uint32
	CorrelationID windows.GUID
}

type rasDialParams struct {
	Size                        uint32
	EntryName                   [257]uint16
	PhoneNumber, CallbackNumber [129]uint16
	UserName, Password          [257]uint16
	Domain                      [16]uint16
	SubEntry                    uint32
	CallbackID                  packedPointer
	IfIndex                     uint32
	EncPassword                 packedPointer
}

type rasDialExtensions struct {
	Size, Options               uint32
	Parent, Reserved, Reserved1 packedPointer
	EapSize                     uint32
	EapInfo                     packedPointer
	SkipPPPAuth, DeviceSize     uint32
	DeviceInfo                  packedPointer
}

type rasEapIdentity struct {
	UserName [257]uint16
	Size     uint32
	// Variable-length native data immediately follows Size, offset 520.
}

type rasStatus struct {
	Size, State, Error            uint32
	DeviceType                    [17]uint16
	DeviceName, PhoneNumber       [129]uint16
	_                             [2]byte // RASTUNNELENDPOINT is DWORD-aligned.
	LocalEndpoint, RemoteEndpoint [20]byte
	Substate                      uint32
}

type rasAttempt struct {
	mu             sync.Mutex
	latest         connectionState
	closing        bool
	hangupAccepted bool
	connected      bool
	id             uintptr
	identity       *rasEapIdentity
}

func (a *rasAttempt) invalidStatus() (connectionState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// RasDial's asynchronous acknowledgement can precede allocation of its
	// port: ERROR_INVALID_HANDLE is transient until a terminal callback.
	terminal := a.connected || a.latest.state == stateDisconnected || a.latest.code != 0
	if (a.closing && a.hangupAccepted) || (terminal && (a.closing || a.connected)) {
		return connectionState{}, errInvalidHandle
	}
	return a.latest, nil
}

type windowsDriver struct {
	phonebook string
	attempt   *rasAttempt
}

// ProtectionEndpoint binds the firewall exception to this dial's current peer.
// Alternate server endpoints/MOBIKE redirects are not implicitly permitted.
func (s *Session) ProtectionEndpoint() (netip.Addr, error) {
	connections := make([]rasConnection, 1)
	connections[0].Size = uint32(unsafe.Sizeof(connections[0]))
	size, count := uint32(unsafe.Sizeof(connections[0])), uint32(0)
	code, _, _ := rasEnumConnections.Call(uintptr(unsafe.Pointer(&connections[0])), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)))
	if code != 0 || count != 1 || connections[0].Handle.get() != s.handle {
		return netip.Addr{}, errors.New("ikev2_connection_ownership_changed")
	}
	status := rasStatus{Size: uint32(unsafe.Sizeof(rasStatus{}))}
	code, _, _ = rasGetConnectStatus.Call(s.handle, uintptr(unsafe.Pointer(&status)))
	if code != 0 || status.State != stateConnected || status.Error != 0 {
		return netip.Addr{}, errors.New("ikev2_connection_not_ready")
	}
	switch binary.LittleEndian.Uint32(status.RemoteEndpoint[:4]) {
	case 1:
		return netip.AddrFrom4([4]byte(status.RemoteEndpoint[4:8])), nil
	case 2:
		return netip.AddrFrom16([16]byte(status.RemoteEndpoint[4:20])), nil
	default:
		return netip.Addr{}, errors.New("ikev2_endpoint_unavailable")
	}
}

// Open uses only the current user's phonebook and saved EAP credentials.
// It does not create/modify profiles, import certificates or display auth UI.
func Open(ctx context.Context, cfg Config) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var sessionID uint32
	if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sessionID) != nil || sessionID == 0 {
		return nil, errors.New("ikev2_requires_foreground_user_session")
	}
	for _, proc := range []*windows.LazyProc{rasGetEntryProperties, rasEnumConnections, rasGetEntryDialParams, rasGetEapUserIdentity, rasFreeEapUserIdentity, rasDial, rasGetConnectStatus, rasHangUp} {
		if proc.Find() != nil {
			return nil, errors.New("ikev2_ras_unavailable")
		}
	}
	appData, err := windows.KnownFolderPath(windows.FOLDERID_RoamingAppData, 0)
	if err != nil {
		return nil, errors.New("ikev2_user_phonebook_unavailable")
	}
	return connect(ctx, cfg, &windowsDriver{phonebook: filepath.Join(appData, "Microsoft", "Network", "Connections", "Pbk", "rasphone.pbk")})
}

func (d *windowsDriver) entry(cfg Config) (rasEntry, error) {
	book, _ := windows.UTF16PtrFromString(d.phonebook)
	name, _ := windows.UTF16PtrFromString(cfg.WindowsProfile)
	// Alternate phone numbers may follow RASENTRY. Bound the entire allocation.
	buffer := make([]uint32, (unsafe.Sizeof(rasEntry{})+64*1024)/4)
	e := (*rasEntry)(unsafe.Pointer(&buffer[0]))
	e.Size = uint32(unsafe.Sizeof(*e))
	size := uint32(len(buffer) * 4)
	code, _, _ := rasGetEntryProperties.Call(uintptr(unsafe.Pointer(book)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(e)), uintptr(unsafe.Pointer(&size)), 0, 0)
	if code != 0 {
		return rasEntry{}, rasError(uint32(code))
	}
	return *e, nil
}

const (
	rasRequireEAP         = 0x00020000
	rasOtherAuth          = 0x00040000 | 0x00080000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000
	rasUnsafeOptions2     = 0x10 | 0x100 | 0x40000 | 0x400000 | 0x800000 | 0x1000000 | 0x4000000 | 0x8000000 | 0x10000000 | 0x20000000
	rasUnsupportedOptions = 0x40 | 0x80 | 0x100000 | 0x80000000 | 0x4000
)

func validateEntry(e rasEntry, cfg Config) error {
	if e.Type != 2 || e.VPNStrategy != 7 || e.CustomAuthKey != 26 || e.Options&rasRequireEAP == 0 || e.Options&rasOtherAuth != 0 {
		return errors.New("ikev2_profile_requires_ikev2_eap_mschapv2")
	}
	// Keep Windows IKE certificate name/EKU checks enabled. Reject PSK, machine
	// auth, third-party/OTP/always-on profiles and independent redial owners.
	if e.Options2&rasUnsafeOptions2 != 0 || e.RedialCount != 0 || e.Options3 != 0 {
		return errors.New("ikev2_unsafe_or_unsupported_windows_profile")
	}
	if !strings.EqualFold(windows.UTF16ToString(e.PhoneNumber[:]), cfg.ServerName) || windows.UTF16ToString(e.IDr[:]) != "" || windows.UTF16ToString(e.IDi[:]) != "" {
		return errors.New("ikev2_server_identity_mismatch")
	}
	if e.Options&0x10 == 0 || e.Options2&0x2000 == 0 || e.NetProtocols != 0xc || (e.EncryptionType != 1 && e.EncryptionType != 2) {
		return errors.New("ikev2_profile_requires_encrypted_dual_stack_default_routes")
	}
	if e.AlternateOffset != 0 || e.SubEntries > 1 || e.IsIMSConfig != 0 || e.Options&rasUnsupportedOptions != 0 || e.Script[0] != 0 || e.AutodialDLL[0] != 0 || e.AutodialFunc[0] != 0 || e.CustomDialDLL[0] != 0 || e.PrerequisiteEntry[0] != 0 || e.PrerequisitePBK[0] != 0 {
		return errors.New("ikev2_profile_contains_unsupported_dial_hooks")
	}
	return nil
}

func (d *windowsDriver) inspect(cfg Config) error {
	e, err := d.entry(cfg)
	if err != nil {
		return err
	}
	if err := validateEntry(e, cfg); err != nil {
		return err
	}
	return noRASConnections()
}

func noRASConnections() error {
	// Do not reference, adopt or disconnect an existing RAS session. This also
	// leaves stale sessions after a process crash for explicit OS-level recovery.
	connections := make([]rasConnection, 1)
	connections[0].Size = uint32(unsafe.Sizeof(connections[0]))
	size, count := uint32(unsafe.Sizeof(connections[0])), uint32(0)
	code, _, _ := rasEnumConnections.Call(uintptr(unsafe.Pointer(&connections[0])), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)))
	if code == 603 || count != 0 {
		return errors.New("ikev2_existing_ras_connection")
	}
	if code != 0 {
		return rasError(uint32(code))
	}
	return nil
}

func (d *windowsDriver) dial(cfg Config) (uintptr, error) {
	// Recheck just before passing control to Windows; no profile settings are
	// changed to make an incompatible profile appear acceptable.
	if err := d.inspect(cfg); err != nil {
		return 0, err
	}
	book, _ := windows.UTF16PtrFromString(d.phonebook)
	name, _ := windows.UTF16PtrFromString(cfg.WindowsProfile)
	params := rasDialParams{Size: uint32(unsafe.Sizeof(rasDialParams{}))}
	defer func() { params = rasDialParams{}; runtime.KeepAlive(&params) }()
	copy(params.EntryName[:], windows.StringToUTF16(cfg.WindowsProfile))
	var hasPassword int32
	code, _, _ := rasGetEntryDialParams.Call(uintptr(unsafe.Pointer(book)), uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&hasPassword)))
	if code != 0 || hasPassword == 0 {
		return 0, errors.New("ikev2_saved_credentials_required")
	}
	// RasGetEntryDialParams returns an opaque saved-password handle, not the
	// plaintext password. Preserve it unchanged for RasDial, then clear it.
	params.PhoneNumber = [129]uint16{}
	params.CallbackNumber = [129]uint16{}
	params.IfIndex = 0
	params.CallbackID = packedPointer{}
	params.EncPassword = packedPointer{}
	var identity *rasEapIdentity
	code, _, _ = rasGetEapUserIdentity.Call(uintptr(unsafe.Pointer(book)), uintptr(unsafe.Pointer(name)), 2, 0, uintptr(unsafe.Pointer(&identity)))
	if code != 0 || identity == nil {
		if identity != nil {
			rasFreeEapUserIdentity.Call(uintptr(unsafe.Pointer(identity)))
		}
		return 0, errors.New("ikev2_saved_eap_identity_required")
	}
	if identity.Size > 1024*1024 {
		rasFreeEapUserIdentity.Call(uintptr(unsafe.Pointer(identity)))
		return 0, errors.New("ikev2_invalid_eap_identity")
	}
	params.UserName = identity.UserName
	d.attempt = &rasAttempt{id: rasAttemptID.Add(1), identity: identity}
	rasAttempts.Store(d.attempt.id, d.attempt)
	params.CallbackID.set(d.attempt.id)
	ext := rasDialExtensions{Size: uint32(unsafe.Sizeof(rasDialExtensions{})), Options: 0x40 | 0x80 | 0x100, EapSize: identity.Size}
	if identity.Size != 0 {
		ext.EapInfo.set(uintptr(unsafe.Pointer(identity)) + unsafe.Offsetof(identity.Size) + 4)
	}
	var h uintptr
	code, _, _ = rasDial.Call(uintptr(unsafe.Pointer(&ext)), uintptr(unsafe.Pointer(book)), uintptr(unsafe.Pointer(&params)), 2, rasNotifier, uintptr(unsafe.Pointer(&h)))
	runtime.KeepAlive(identity)
	if h == 0 {
		d.release()
	}
	if code != 0 {
		return h, rasError(uint32(code))
	}
	return h, nil
}

func (d *windowsDriver) status(h uintptr) (connectionState, error) {
	s := rasStatus{Size: uint32(unsafe.Sizeof(rasStatus{}))}
	code, _, _ := rasGetConnectStatus.Call(h, uintptr(unsafe.Pointer(&s)))
	if code == 6 && d.attempt != nil {
		return d.attempt.invalidStatus()
	}
	if code != 0 {
		return connectionState{}, rasError(uint32(code))
	}
	if s.State == stateConnected && d.attempt != nil {
		d.attempt.mu.Lock()
		d.attempt.connected = true
		d.attempt.mu.Unlock()
	}
	return connectionState{state: s.State, code: s.Error}, nil
}

func (d *windowsDriver) hangup(h uintptr) error {
	if d.attempt != nil {
		d.attempt.mu.Lock()
		d.attempt.closing = true
		d.attempt.mu.Unlock()
	}
	code, _, _ := rasHangUp.Call(h)
	if code == 0 && d.attempt != nil {
		d.attempt.mu.Lock()
		d.attempt.hangupAccepted = true
		d.attempt.mu.Unlock()
	}
	if (code == 6 || code == 668) && d.attempt != nil {
		d.attempt.mu.Lock()
		latest := d.attempt.latest
		connected := d.attempt.connected
		d.attempt.mu.Unlock()
		if !connected && latest.state != stateDisconnected && latest.code == 0 {
			return errDialPending
		}
		return errInvalidHandle
	}
	if code != 0 {
		return rasError(uint32(code))
	}
	return nil
}

func (d *windowsDriver) release() {
	if d.attempt == nil {
		return
	}
	rasAttempts.Delete(d.attempt.id)
	if d.attempt.identity != nil {
		rasFreeEapUserIdentity.Call(uintptr(unsafe.Pointer(d.attempt.identity)))
		d.attempt.identity = nil
	}
}
