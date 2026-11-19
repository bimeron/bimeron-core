//go:build windows

package releasecard

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	winscard             = syscall.NewLazyDLL("winscard.dll")
	procEstablishContext = winscard.NewProc("SCardEstablishContext")
	procReleaseContext   = winscard.NewProc("SCardReleaseContext")
	procListReaders      = winscard.NewProc("SCardListReadersW")
	procConnect          = winscard.NewProc("SCardConnectW")
	procDisconnect       = winscard.NewProc("SCardDisconnect")
	procBeginTransaction = winscard.NewProc("SCardBeginTransaction")
	procEndTransaction   = winscard.NewProc("SCardEndTransaction")
	procTransmit         = winscard.NewProc("SCardTransmit")
	scardPCIT1           = winscard.NewProc("g_rgSCardT1Pci")
)

const (
	scardScopeUser       = uintptr(0)
	scardShareShared     = uintptr(2)
	scardProtocolT1      = uintptr(2)
	scardLeaveCard       = uintptr(0)
	scardResetCard       = uintptr(1)
	scardENoReadersAvail = uintptr(0x8010002E)
)

type pcscContext struct{ handle uintptr }

type pcscCard struct {
	handle uintptr
}

func scardError(op string, rc uintptr) error {
	return fmt.Errorf("%s: PC/SC error 0x%08X", op, uint32(rc))
}

func openContext() (*pcscContext, error) {
	if err := winscard.Load(); err != nil {
		return nil, err
	}
	var h uintptr
	rc, _, _ := procEstablishContext.Call(scardScopeUser, 0, 0, uintptr(unsafe.Pointer(&h)))
	if rc != 0 {
		return nil, scardError("SCardEstablishContext", rc)
	}
	return &pcscContext{h}, nil
}

func (c *pcscContext) Close() error {
	rc, _, _ := procReleaseContext.Call(c.handle)
	if rc != 0 {
		return scardError("SCardReleaseContext", rc)
	}
	return nil
}

func (c *pcscContext) Readers() ([]string, error) {
	var size uint32
	rc, _, _ := procListReaders.Call(c.handle, 0, 0, uintptr(unsafe.Pointer(&size)))
	if rc == scardENoReadersAvail {
		return nil, errNoReaders
	}
	if rc != 0 {
		return nil, scardError("SCardListReaders", rc)
	}
	buf := make([]uint16, size)
	rc, _, _ = procListReaders.Call(c.handle, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if rc == scardENoReadersAvail {
		return nil, errNoReaders
	}
	if rc != 0 {
		return nil, scardError("SCardListReaders", rc)
	}
	var readers []string
	start := 0
	for i, ch := range buf[:size] {
		if ch == 0 {
			if i > start {
				readers = append(readers, syscall.UTF16ToString(buf[start:i]))
			}
			start = i + 1
		}
	}
	return readers, nil
}

// Connect opens the reader and holds a PC/SC transaction so no other process
// can interleave APDUs with an authenticated signing session.
func (c *pcscContext) Connect(reader string) (*pcscCard, error) {
	name, err := syscall.UTF16PtrFromString(reader)
	if err != nil {
		return nil, err
	}
	var h uintptr
	var proto uint32
	rc, _, _ := procConnect.Call(c.handle, uintptr(unsafe.Pointer(name)), scardShareShared, scardProtocolT1, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&proto)))
	if rc != 0 {
		return nil, scardError("SCardConnect", rc)
	}
	rc, _, _ = procBeginTransaction.Call(h)
	if rc != 0 {
		procDisconnect.Call(h, scardLeaveCard)
		return nil, scardError("SCardBeginTransaction", rc)
	}
	return &pcscCard{h}, nil
}

// Close resets the card so a verified PIN does not outlive this process.
func (c *pcscCard) Close() error {
	procEndTransaction.Call(c.handle, scardResetCard)
	rc, _, _ := procDisconnect.Call(c.handle, scardResetCard)
	if rc != 0 {
		return scardError("SCardDisconnect", rc)
	}
	return nil
}

func (c *pcscCard) Transmit(command []byte) ([]byte, error) {
	if len(command) == 0 {
		return nil, errors.New("empty APDU")
	}
	if err := scardPCIT1.Find(); err != nil {
		return nil, err
	}
	resp := make([]byte, 65538)
	n := uint32(len(resp))
	rc, _, _ := procTransmit.Call(c.handle, scardPCIT1.Addr(), uintptr(unsafe.Pointer(&command[0])), uintptr(len(command)), 0, uintptr(unsafe.Pointer(&resp[0])), uintptr(unsafe.Pointer(&n)))
	if rc != 0 {
		return nil, scardError("SCardTransmit", rc)
	}
	return resp[:n], nil
}
