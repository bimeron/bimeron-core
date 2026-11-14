package winres

import (
	"bytes"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	shell32         = windows.NewLazySystemDLL("shell32.dll")
	user32          = windows.NewLazySystemDLL("user32.dll")
	extractIconEx   = shell32.NewProc("ExtractIconExW")
	destroyIcon     = user32.NewProc("DestroyIcon")
	dataFileLoading = uintptr(windows.LOAD_LIBRARY_AS_DATAFILE | windows.LOAD_LIBRARY_AS_IMAGE_RESOURCE)
)

// TestWindowsReadsResources checks the linked resources with the Windows
// APIs that Explorer and the file properties dialog use, independently of
// this package's reader.
func TestWindowsReadsResources(t *testing.T) {
	ico := sourceIcon(t)
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			obj, err := Object(arch, ico, "0.4.0-beta.1")
			if err != nil {
				t.Fatal(err)
			}
			exe := buildWindows(t, arch, obj)

			path, err := syscall.UTF16PtrFromString(exe)
			if err != nil {
				t.Fatal(err)
			}
			count, _, _ := extractIconEx.Call(uintptr(unsafe.Pointer(path)), ^uintptr(0), 0, 0, 0)
			if count != 1 {
				t.Fatalf("ExtractIconEx found %d icons, want 1", count)
			}
			var large, small windows.Handle
			if n, _, _ := extractIconEx.Call(uintptr(unsafe.Pointer(path)), 0, uintptr(unsafe.Pointer(&large)), uintptr(unsafe.Pointer(&small)), 1); n == 0 || large == 0 || small == 0 {
				t.Fatalf("ExtractIconEx extracted %d icons", n)
			}
			destroyIcon.Call(uintptr(large))
			destroyIcon.Call(uintptr(small))

			module, err := windows.LoadLibraryEx(exe, 0, dataFileLoading)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.FreeLibrary(module)
			images, _ := ParseICO(ico)
			for i, image := range images {
				info, err := windows.FindResource(module, windows.ResourceID(i+1), windows.RT_ICON)
				if err != nil {
					t.Fatalf("icon %d: %v", i+1, err)
				}
				data, err := windows.LoadResourceData(module, info)
				if err != nil || !bytes.Equal(data, image.Data) {
					t.Fatalf("icon %d differs from the source image: %v", i+1, err)
				}
			}

			size, err := windows.GetFileVersionInfoSize(exe, nil)
			if err != nil {
				t.Fatal(err)
			}
			block := make([]byte, size)
			if err := windows.GetFileVersionInfo(exe, 0, size, unsafe.Pointer(&block[0])); err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]string{
				"ProductName":      ProductName,
				"FileDescription":  ProductName,
				"CompanyName":      CompanyName,
				"ProductVersion":   "0.4.0-beta.1",
				"FileVersion":      "0.4.0-beta.1",
				"OriginalFilename": OriginalFilename,
			} {
				var value *uint16
				var n uint32
				if err := windows.VerQueryValue(unsafe.Pointer(&block[0]), `\StringFileInfo\`+stringTableKey+`\`+key, unsafe.Pointer(&value), &n); err != nil {
					t.Fatalf("%s: %v", key, err)
				}
				if got := windows.UTF16PtrToString(value); got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
			var fixed *windows.VS_FIXEDFILEINFO
			var n uint32
			if err := windows.VerQueryValue(unsafe.Pointer(&block[0]), `\`, unsafe.Pointer(&fixed), &n); err != nil {
				t.Fatal(err)
			}
			if fixed.Signature != fixedSignature || fixed.FileVersionMS != 0<<16|4 || fixed.FileVersionLS != 0 || fixed.FileFlags&fixedPrerelease == 0 {
				t.Fatalf("fixed file info %+v", *fixed)
			}
		})
	}
}
