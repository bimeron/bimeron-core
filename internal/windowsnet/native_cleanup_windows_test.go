//go:build windows

package windowsnet

import (
	"testing"

	"golang.org/x/sys/windows"
)

// A tunnel adapter that disappeared took its routes and addresses with it;
// cleanup must succeed so the session can reopen a new adapter.
func TestNativeCleanupAfterAdapterVanished(t *testing.T) {
	const tag = "BimeronCore:vanished-adapter-test"
	ownedNative.Lock()
	ownedNative.byTag[tag] = &nativeResources{adapter: windows.GUID{Data1: 1}, index: 0x7ffffff0, routes: []windows.MibIpForwardRow2{{}}}
	ownedNative.Unlock()
	if err := nativeCleanup(Config{Tag: tag}); err != nil {
		t.Fatal(err)
	}
	ownedNative.Lock()
	_, kept := ownedNative.byTag[tag]
	ownedNative.Unlock()
	if kept {
		t.Fatal("cleanup kept resources of a vanished adapter")
	}
}
