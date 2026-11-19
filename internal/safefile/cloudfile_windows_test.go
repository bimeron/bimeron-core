package safefile

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Cloud Files API (cldapi.dll), used to create a real cloud-file placeholder.
var (
	cldapi                 = windows.NewLazySystemDLL("cldapi.dll")
	procCfRegisterSyncRoot = cldapi.NewProc("CfRegisterSyncRoot")
	procCfUnregisterRoot   = cldapi.NewProc("CfUnregisterSyncRoot")
	procCfConvertToPlace   = cldapi.NewProc("CfConvertToPlaceholder")
)

// cfSyncRegistration is CF_SYNC_REGISTRATION.
type cfSyncRegistration struct {
	StructSize             uint32
	ProviderName           *uint16
	ProviderVersion        *uint16
	SyncRootIdentity       unsafe.Pointer
	SyncRootIdentityLength uint32
	FileIdentity           unsafe.Pointer
	FileIdentityLength     uint32
	ProviderID             windows.GUID
}

// cfSyncPolicies is CF_SYNC_POLICIES.
type cfSyncPolicies struct {
	StructSize                       uint32
	HydrationPrimary, HydrationMod   uint16
	PopulationPrimary, PopulationMod uint16
	InSync, HardLink, Placeholder    uint32
}

const (
	cfHydrationFull         = 2
	cfPopulationAlwaysFull  = 3
	cfConvertFlagMarkInSync = 1
)

func hresult(r uintptr) error {
	if int32(r) < 0 {
		return windows.Errno(r)
	}
	return nil
}

// cloudPlaceholder registers a temporary sync root and converts a local file
// in it into an in-sync cloud-file placeholder, like the files a sync client
// such as OneDrive keeps. It returns the placeholder path.
func cloudPlaceholder(t *testing.T, data []byte) string {
	t.Helper()
	unavailable := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("BIMERON_REQUIRE_CLOUD_FILE") == "1" {
			t.Fatalf(format, args...)
		}
		t.Skipf(format, args...)
	}
	if err := cldapi.Load(); err != nil {
		unavailable("Cloud Files API unavailable: %v", err)
	}
	root := t.TempDir()
	rootName, _ := windows.UTF16PtrFromString(root)
	name, _ := windows.UTF16PtrFromString("Bimeron safefile test")
	version, _ := windows.UTF16PtrFromString("1.0")
	identity := []byte("bimeron-safefile-test")
	registration := cfSyncRegistration{
		ProviderName:           name,
		ProviderVersion:        version,
		SyncRootIdentity:       unsafe.Pointer(&identity[0]),
		SyncRootIdentityLength: uint32(len(identity)),
		ProviderID:             windows.GUID{Data1: 0x6b1d5b8e, Data2: 0x2f0c, Data3: 0x4c55, Data4: [8]byte{0x9a, 0x3e, 0x51, 0x8f, 0x0c, 0x4d, 0x7a, 0x21}},
	}
	registration.StructSize = uint32(unsafe.Sizeof(registration))
	policies := cfSyncPolicies{HydrationPrimary: cfHydrationFull, PopulationPrimary: cfPopulationAlwaysFull}
	policies.StructSize = uint32(unsafe.Sizeof(policies))
	r, _, _ := procCfRegisterSyncRoot.Call(uintptr(unsafe.Pointer(rootName)), uintptr(unsafe.Pointer(&registration)), uintptr(unsafe.Pointer(&policies)), 0)
	if err := hresult(r); err != nil {
		unavailable("CfRegisterSyncRoot: %v", err)
	}
	// Registered after TempDir, so it runs before the directory is removed.
	t.Cleanup(func() { procCfUnregisterRoot.Call(uintptr(unsafe.Pointer(rootName))) })

	path := filepath.Join(root, "file")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	pathName, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(pathName, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	fileIdentity := []byte("file")
	var usn int64
	r, _, _ = procCfConvertToPlace.Call(uintptr(h), uintptr(unsafe.Pointer(&fileIdentity[0])), uintptr(len(fileIdentity)), cfConvertFlagMarkInSync, uintptr(unsafe.Pointer(&usn)), 0)
	windows.CloseHandle(h)
	if err := hresult(r); err != nil {
		t.Fatalf("CfConvertToPlaceholder: %v", err)
	}
	return path
}

// TestReadCloudFilePlaceholder reads a cloud-file placeholder that the test
// creates with the Cloud Files API. CI sets BIMERON_REQUIRE_CLOUD_FILE=1 so
// that the test fails instead of skipping when the API is unavailable.
func TestReadCloudFilePlaceholder(t *testing.T) {
	path := cloudPlaceholder(t, []byte("cloud data"))
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Type() != fs.ModeIrregular {
		t.Fatalf("placeholder has mode %v, want a reparse-point data file", info.Mode())
	}
	if tag := openedReparseTag(t, path); tag&^0xf000 != 0x9000001a {
		t.Fatalf("placeholder has reparse tag %#x, want IO_REPARSE_TAG_CLOUD", tag)
	}
	if b, err := Read(path, 16); err != nil || string(b) != "cloud data" {
		t.Fatalf("Read() = %q, %v", b, err)
	}
	if _, err := Read(path, 4); err != ErrTooLarge {
		t.Fatalf("Read(limit 4) = %v, want ErrTooLarge", err)
	}
}

func openedReparseTag(t *testing.T, path string) uint32 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var tag uint32
	var tagErr error
	if err := c.Control(func(fd uintptr) { _, tag, _, tagErr = attributeTag(windows.Handle(fd)) }); err != nil || tagErr != nil {
		t.Fatal(err, tagErr)
	}
	return tag
}
