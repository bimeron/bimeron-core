//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

type restoreIntent struct {
	Request       heldRestoreRequest `json:"request"`
	Owner         string             `json:"owner"`
	InitialSHA256 string             `json:"initial_sha256"`
	BrokerSHA256  string             `json:"broker_sha256"`
	BrokerPID     uint32             `json:"broker_pid"`
	BrokerCreated uint64             `json:"broker_created"`
}
type restoreReceipt struct {
	Operation  string        `json:"operation_id"`
	Instance   string        `json:"committing_instance"`
	Profile    string        `json:"profile_id"`
	Generation string        `json:"filter_generation"`
	Target     restoreTarget `json:"target"`
}

// Store in the machine-protected service directory. Publish without replacement.
// A crash before rename leaves only a uniquely named, inert temporary file.
func publishRestoreRecord(directory, operation, kind string, value any) error {
	path, err := restoreRecordPath(directory, operation, kind)
	if err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := path + "." + hex.EncodeToString(nonce[:]) + ".tmp"
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(from, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	f := os.NewFile(uintptr(h), tmp)
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
func restoreRecordPath(directory, operation, kind string) (string, error) {
	if !filepath.IsAbs(directory) || !restoreHex(operation, 32) || (kind != "intent" && kind != "receipt" && kind != "claim") {
		return "", errors.New("invalid restore record path")
	}
	return filepath.Join(directory, "restore-"+operation+"."+kind+".json"), nil
}
func readRestoreRecord(directory, operation, kind string, value any) error {
	path, err := restoreRecordPath(directory, operation, kind)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return err
	}
	if len(b) > 8192 {
		return errors.New("oversize restore record")
	}
	return json.Unmarshal(b, value)
}
